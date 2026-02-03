import os
import json
import hmac
import hashlib
import time
import urllib.parse
import urllib.request
import re 

# 環境変数を取得
SLACK_SIGNING_SECRET = os.environ.get("SLACK_SIGNING_SECRET", "")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
DOCBASE_TOKEN = os.environ.get("DOCBASE_TOKEN", "")
DOCBASE_HOST = os.environ.get("DOCBASE_HOST", "https://api.docbase.io")

def verify_slack_signature(headers, body: bytes) -> bool:
    ts = headers.get("X-Slack-Request-Timestamp", "")
    sig = headers.get("X-Slack-Signature", "")
    
    print(f"Timestamp: {ts}, Signature: {sig}")

    if not ts or not sig:
        print("Signature or timestamp missing.")
        return False

    current_time = time.time()
    time_diff = abs(current_time - int(ts))
    print(f"Time difference: {time_diff} seconds")
    if time_diff > 60 * 5:
        print("Timestamp validation failed.")
        return False

    base = f"v0:{ts}:{body.decode('utf-8')}"
    digest = hmac.new(SLACK_SIGNING_SECRET.encode(), base.encode(), hashlib.sha256).hexdigest()
    expected_sig = f"v0={digest}"
    
    print(f"Expected Signature: {expected_sig}")
    print(f"Received Signature: {sig}")

    if not hmac.compare_digest(expected_sig, sig):
        print("Signature validation failed.")
        return False
    
    print("Signature validation successful.")
    return True

def fetch_docbase_article(url: str):
    # --- デバッグログ ---
    # 実行時にLambdaが読み込んでいるトークンの先頭8文字をログに出力
    token_preview = (DOCBASE_TOKEN or "")[:8]
    print(f"Using DocBase Token starting with: {token_preview}...")
    # --- ここまで ---

    parsed = urllib.parse.urlparse(url)
    path_parts = parsed.path.strip("/").split("/")
    if len(path_parts) < 2 or path_parts[-2] != "posts":
        print(f"URL path does not match expected format: {parsed.path}")
        return None
    
    team_name = parsed.hostname.split('.')[0]
    post_id = path_parts[-1]
    
    # --- ★ チーム名と記事IDのログ出力（追加） ---
    print(f"Extracted Team: '{team_name}', Post ID: '{post_id}'")
    # --- ここまで ---
    
    api_url = f"{DOCBASE_HOST}/teams/{team_name}/posts/{post_id}"
    print(f"Requesting DocBase API URL: {api_url}")

    req = urllib.request.Request(api_url, headers={
        "X-DocBaseToken": DOCBASE_TOKEN,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                print(f"DocBase API returned status {resp.status}")
                return None
            return json.load(resp)
    except Exception as e:
        print(f"Failed to fetch DocBase article from URL: {url}")
        print(f"Error details: {e}")
        return None

def build_unfurl(article):
    if not article:
        return None
    title = article.get("title", "Docbase")
    url = article.get("url")

    # 1. bodyを取得
    raw_body = article.get("body") or ""
    
    # 2. 簡単なMarkdownを除去してプレーンテキストに近づける
    #    - 見出し記号 (#) を削除
    #    - リンク ([text](url)) を text に変換
    #    - 強調 (*, _, ~) 記号を削除
    #    - 画像 (![alt](src)) を削除
    #    - 水平線 (---, ***) を削除
    #    - 引用 (>) を削除
    plain_body = re.sub(r'#+\s?', '', raw_body)
    plain_body = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', plain_body)
    plain_body = re.sub(r'(\*|_|~)', '', plain_body)
    plain_body = re.sub(r'!\[[^\]]*\]\([^\)]*\)', '', plain_body)
    plain_body = re.sub(r'(\n---\n|\n\*\*\*\n)', '\n', plain_body)
    plain_body = re.sub(r'^\s*>\s?', '', plain_body, flags=re.MULTILINE)

    # 3. 改行を詰めて、100文字に切り出す
    body = " ".join(plain_body.splitlines())[:100] + "..."

    return {
        "title": f":docbase: DocBase",
        "text": f"<{url}|*{title}*> \n {body}",
        "footer": f"Docbase • {article.get('user', {}).get('name','')}",
    }

def is_public_docbase_article(article: dict) -> bool:
    # Allow only public-to-everyone posts; exclude group-limited or unknown scope.
    scope = article.get("scope")
    groups = article.get("groups") or []
    if scope not in ("everyone", "public"):
        return False
    if groups:
        return False
    return True

def slack_request(path, payload):
    req = urllib.request.Request(
        f"https://slack.com/api/{path}",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.load(resp)
            # --- ここが重要：エラーなら内容を叫ぶ ---
            if not body.get("ok"):
                print(f"!!! Slack API Error in {path} !!!")
                print(f"Error Code: {body.get('error')}") # ←これが犯人です
                print(f"Error Details: {body}")
            else:
                print(f"Slack API Success: {path}")
            # ------------------------------------
            return body
    except Exception as e:
        print(f"Failed to send Slack request: {e}")
        return None

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")

    try:
        # 自分自身の情報を問い合わせる
        auth_test_req = urllib.request.Request(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}"},
            method="POST"
        )
        with urllib.request.urlopen(auth_test_req) as res:
            auth_data = json.load(res)
            print(f"★ AUTH TEST: {json.dumps(auth_data)}")
            
            # 重要: ここで権限の中身を見る
            if res.headers.get("x-oauth-scopes"):
                print(f"★ CURRENT SCOPES: {res.headers.get('x-oauth-scopes')}")
            else:
                print("★ SCOPES NOT FOUND IN HEADERS")
    except Exception as e:
        print(f"★ AUTH TEST FAILED: {e}")
    # ------------------------------------

    body = event.get("body", "") or ""
    raw_body = body.encode("utf-8")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    
    slack_headers = {
        "X-Slack-Request-Timestamp": headers.get("x-slack-request-timestamp"),
        "X-Slack-Signature": headers.get("x-slack-signature"),
    }

    if not verify_slack_signature(slack_headers, raw_body):
        print("Returning 401 due to invalid signature.")
        return {"statusCode": 401, "body": "invalid signature"}

    payload = json.loads(body)
    if payload.get("type") == "url_verification":
        print("Handling url_verification.")
        return {"statusCode": 200, "body": payload.get("challenge","")}

    if payload.get("type") == "event_callback":
        print("Handling event_callback.")
        ev = payload.get("event", {})
        if ev.get("type") == "link_shared":
            channel = ev.get("channel")
            msg_ts = ev.get("message_ts")
            unfurls = {}
            for link in ev.get("links", []):
                url = link.get("url")
                if "docbase.io/posts/" not in (url or ""):
                    continue
                article = fetch_docbase_article(url)
                if article and not is_public_docbase_article(article):
                    print(f"Skipping non-public DocBase article: {url}")
                    continue
                card = build_unfurl(article)
                if card:
                    unfurls[url] = card
            if unfurls:
                print(f"Sending unfurl data: {json.dumps(unfurls)}")
                slack_request("chat.unfurl", {"channel": channel, "ts": msg_ts, "unfurls": unfurls})
        return {"statusCode": 200, "body": ""}

    return {"statusCode": 200, "body": ""}
