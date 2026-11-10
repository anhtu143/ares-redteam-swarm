# TOOL: C2 INTEGRATION WRAPPER

## Description
This module allows ARES to interact programmatically with C2 frameworks (like Mythic or Sliver) to spawn beacons, issue commands, and retrieve output without manual GUI interaction.

## Mythic API Interaction (Python Example)

```python
import requests
import json

class MythicController:
    def __init__(self, server_url, api_token):
        self.url = server_url
        self.headers = {
            "apitoken": api_token,
            "Content-Type": "application/json"
        }

    def issue_task(self, callback_id, command, params):
        data = {
            "command": command,
            "params": params,
            "callback_id": callback_id
        }
        res = requests.post(f"{self.url}/api/v1.4/tasking/create_and_issue", headers=self.headers, json=data)
        return res.json()

    def get_output(self, task_id):
        res = requests.get(f"{self.url}/api/v1.4/responses/{task_id}", headers=self.headers)
        return res.json()
```

## Usage in Operations
When `[AGENT: SHADOW]` needs to execute a lateral movement command via an established beacon, it will invoke this wrapper rather than asking the USER to do it manually in the C2 console.
