"""Command-line wrapper for the extracted PayPal Guest handoff module.

This is an additive narrow entrypoint used by ``payment.py`` and diagnostics so PayPal Guest behavior can evolve outside the monolithic legacy payment module.
"""

from __future__ import annotations

import argparse
import json

from paypal_guest import PAYPAL_GUEST_US_PROXY, paypal_guest_handoff_fill_nonpayment


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PayPal Guest handoff only")
    parser.add_argument("redirect_url", help="PayPal redirect/checkout URL")
    parser.add_argument("--email", default="", help="ChatGPT/account email to fill on PayPal Guest")
    parser.add_argument("--proxy", default=PAYPAL_GUEST_US_PROXY, help="Proxy URL for PayPal Guest browser")
    parser.add_argument("--json-result", action="store_true", help="Print PAYPAL_GUEST_RESULT_JSON=...")
    args = parser.parse_args()

    result = paypal_guest_handoff_fill_nonpayment(
        args.redirect_url,
        chatgpt_email=args.email,
        proxy_url=args.proxy,
    )
    if args.json_result:
        print("PAYPAL_GUEST_RESULT_JSON=" + json.dumps(result, ensure_ascii=False), flush=True)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
