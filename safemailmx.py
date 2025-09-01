import dns.resolver
import concurrent.futures
import time
import re
import threading
import socket
from tqdm import tqdm
import sys  # Added import to fix NameError

def is_connected(timeout=3):
    endpoints = [("8.8.8.8", 53), ("www.google.com", 80)]
    for host, port in endpoints:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False

def wait_for_internet_connection(check_interval=5):
    while not is_connected():
        print("No internet connection. Waiting for connection...")
        time.sleep(check_interval)

def is_valid_domain(domain):
    if not domain or len(domain) > 253:
        return False
    if '..' in domain:
        return False
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        return False
    return True

def get_mx_record(domain):
    resolver = dns.resolver.Resolver()
    while True:
        try:
            answers = resolver.resolve(domain, 'MX')
            mx_records = sorted(answers, key=lambda r: r.preference)
            return str(mx_records[0].exchange).rstrip('.')
        except dns.resolver.NXDOMAIN:
            return "Domain Does Not Exist"
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
            if not is_connected():
                print(f"❌ No internet. Waiting to retry DNS for: {domain}")
                wait_for_internet_connection()
                continue
            return "No MX Record"
        except Exception as e:
            return f"ERROR: {str(e)}"

EMAIL_REGEX = re.compile(
    r"^(?!.*\.\.)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)

HONEYPOT_DOMAINS = set([
    "0-mail.com", "0815.ru", "10minutemail.com", "20minutemail.com", "2prong.com", "anonbox.net", "binkmail.com",
    "bouncemail.org", "boximail.com", "byom.de", "deadaddress.com", "discard.email", "disposeamail.com",
    "disposableinbox.com", "email60.com", "emailondeck.com", "fakeinbox.com", "getairmail.com", "guerrillamail.com",
    "hottempmail.com", "incognitomail.com", "jetable.org", "kasmail.com", "letthemeatspam.com", "mailcatch.com",
    "maildrop.cc", "mailexpire.com", "mailforspam.com", "mailhazard.com", "mailimate.com", "mailin8r.com",
    "mailinator.com", "mailnesia.com", "mailnull.com", "mailsac.com", "mintemail.com", "mytrashmail.com", "nobulk.com",
    "noclickemail.com", "nowmymail.com", "oneoffemail.com", "putthisinyourspamdatabase.com", "rhyta.com",
    "sharklasers.com", "smellfear.com", "spam4.me", "spamavert.com", "spamex.com", "spamgourmet.com",
    "spamhereplease.com", "spaminator.de", "spamobox.com", "spamspot.com", "spamthis.co.uk", "temp-mail.org",
    "tempmail.io", "tempmail.net", "tempmailbox.com", "tempmailer.com", "temporaryemail.net", "trashmail.com",
    "trashmail.de", "trashmail.me", "trashmail.net", "yopmail.com", "zippymail.info", "tempr.email", "dispostable.com",
    "getnada.com", "dropmail.me", "inboxkitten.com", "meltmail.com", "moakt.com", "emailfake.com",
    "emailtemporario.com.br", "mail-temp.com", "emailsensei.com", "easytrashmail.com", "simplelogin.com",
    "mail7.io", "maildim.com", "mailpoof.com", "mailtothis.com", "email-fake.com", "proxymail.eu", "luxusmail.org",
    "owlymail.com", "shortmail.com", "fakebox.org", "anonaddy.com", "mytemp.email"
])

SPAMTRAP_DOMAINS = set([
    "yahoo.com", "ymail.com", "rocketmail.com", "sbcglobal.net", "att.net", "bellsouth.net",
    "pacbell.net", "swbell.net", "nvbell.net", "ameritech.net", "flash.net", "prodigy.net",
    "snet.net", "wans.net", "ymail.co.uk", "yahoo.co.uk", "yahoo.ca", "aol.com",
    "icloud.com", "mac.com", "me.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "passport.com", "windowslive.com", "gmail.com",
    "verizon.net", "frontier.com", "frontiernet.net", "netzero.net", "peoplepc.com",
    "naver.com", "163.com",
    "comcast.net", "xfinity.com",
    "protonmail.com",
    "seznam.cz", "yandex.ru", "rambler.ru",
    "spectrum.net", "charter.net", "rr.com", "roadrunner.com", "twc.com", "hawaii.rr.com", "adelphia.net"
])

def is_spamtrap_domain(domain, mx_record=None):
    domain = domain.lower()
    
    blocked_tlds = (
        ".ru", ".cn", ".br", ".in", ".vn", ".pl", ".ro", ".cz", ".id", ".ng", ".gh",
        ".tr", ".ph", ".kz", ".kr", ".de", ".ua",
        ".it", ".fr", ".es", ".pt", ".gr",
        ".hu", ".bg", ".by", ".ir", ".th"
    )
    
    if (
        domain in SPAMTRAP_DOMAINS
        or any(domain.endswith(tld) for tld in blocked_tlds)
    ):
        return True
    
    if mx_record:
        mx_record = mx_record.lower()
        if (
            "google.com" in mx_record or
            "outlook.com" in mx_record or
            "yahoodns.net" in mx_record or
            "mimecast.com" in mx_record or
            "office365.com" in mx_record
        ):
            return True

    return False

def is_honeypot_domain(domain):
    return domain.lower() in HONEYPOT_DOMAINS

def process_email(email, output_file, error_output_file, honeypot_output_file, spamtrap_output_file, lock):
    email = email.strip().lower()

    if not EMAIL_REGEX.match(email):
        with lock, open(error_output_file, "a", encoding="utf-8") as f:
            f.write(f"INVALID_FORMAT,{email},\n")
        return None, None

    domain = email.split('@')[1].strip().strip('.').lower()

    if not is_valid_domain(domain):
        with lock, open(error_output_file, "a", encoding="utf-8") as f:
            f.write(f"INVALID_DOMAIN,{email},{domain}\n")
        return None, None

    if is_honeypot_domain(domain):
        with lock, open(honeypot_output_file, "a", encoding="utf-8") as f:
            f.write(f"HONEYPOT_DOMAIN,{email},{domain}\n")
        return None, None

    mx_record = get_mx_record(domain)

    if is_spamtrap_domain(domain, mx_record):
        with lock, open(spamtrap_output_file, "a", encoding="utf-8") as f:
            f.write(f"SPAMTRAP_DOMAIN,{email},{domain},{mx_record}\n")
        return None, None

    if mx_record in ["Domain Does Not Exist", "No MX Record", "Empty Domain"] or mx_record.startswith("ERROR"):
        with lock, open(error_output_file, "a", encoding="utf-8") as f:
            f.write(f"{mx_record},{email},{domain}\n")
    else:
        with lock, open(output_file, "a", encoding="utf-8") as f:
            f.write(f"{email},{mx_record}\n")
        with lock, open("sorted_emails.txt", "a", encoding="utf-8") as f:
            f.write(f"{email}\n")

    return email, mx_record

def sort_emails_by_mx(input_file, output_file, error_output_file, honeypot_output_file, spamtrap_output_file):
    emails = []
    encodings = ['utf-8', 'latin-1', 'windows-1252']
    
    # Count lines for tqdm progress bar
    total_lines = 0
    for encoding in encodings:
        try:
            with open(input_file, "r", encoding=encoding, errors='replace') as file:
                total_lines = sum(1 for line in file if line.strip())
            break
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            print(f"Error: File {input_file} not found.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading {input_file}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"Error: Could not decode {input_file} with tried encodings.", file=sys.stderr)
        sys.exit(1)

    print(f"\n📊 Processing {total_lines} emails to find MX records...")

    lock = threading.Lock()

    # Process file line by line to avoid MemoryError
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for encoding in encodings:
            try:
                with open(input_file, "r", encoding=encoding, errors='replace') as file:
                    for line in tqdm(file, total=total_lines, desc="🔍 Fetching MX Records", unit=" email"):
                        email = line.strip().lower()
                        if email:
                            futures.append(
                                executor.submit(
                                    process_email, email, output_file, error_output_file, 
                                    honeypot_output_file, spamtrap_output_file, lock
                                )
                            )
                break
            except UnicodeDecodeError:
                continue
            except FileNotFoundError:
                print(f"Error: File {input_file} not found.", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                print(f"Error reading {input_file}: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"Error: Could not decode {input_file} with tried encodings.", file=sys.stderr)
            sys.exit(1)

        # Wait for all futures to complete
        concurrent.futures.wait(futures)

    print(f"🚫 Spamtraps saved to: {spamtrap_output_file}")
    print(f"\n✅ Sorting completed! Saved to: {output_file}")
    print(f"⚠️ Honeypots saved to: {honeypot_output_file}")
    print(f"🚨 Errors saved to: {error_output_file}")

# === ENTRY POINT ===
if __name__ == "__main__":
    input_file = input("📂 Enter the path to your .txt email list file: ").strip()
    output_file = "sorted_emails_by_mx.txt"
    error_output_file = "error_domains.txt"
    honeypot_output_file = "honeypot_domains.txt"
    spamtrap_output_file = "spamtrap.txt"

    open(output_file, "w").close()
    open(error_output_file, "w").close()
    open(honeypot_output_file, "w").close()
    open(spamtrap_output_file, "w").close()

    sort_emails_by_mx(input_file, output_file, error_output_file, honeypot_output_file, spamtrap_output_file)
