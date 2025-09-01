# Email Domain Filter

## Overview

The **Email Domain Filter** is a Python script designed to process a list of email addresses from a text file, extract their domains, validate them, and filter out potentially problematic domains, such as honeypots, spamtraps, and invalid domains. The script also retrieves MX (Mail Exchange) records for valid domains to ensure they are operational and not associated with known spamtrap providers. It is optimized to handle large input files efficiently and robustly manages encoding issues.

## Features

- **Email Extraction and Validation**: Extracts email addresses from a text file using a regular expression and validates their format and domain structure.
- **Honeypot and Spamtrap Filtering**: Identifies and filters out domains known to be honeypots (temporary or disposable email services) and spamtraps (domains associated with major providers like Gmail, Yahoo, or specific TLDs).
- **MX Record Checking**: Queries DNS to retrieve MX records for each domain, ensuring the domain is capable of receiving emails.
- **Encoding Robustness**: Handles files with various encodings (UTF-8, Latin-1, Windows-1252) to prevent decoding errors.
- **Memory Efficiency**: Processes large files line by line to avoid memory exhaustion.
- **Concurrent Processing**: Uses multithreading to speed up MX record lookups.
- **Progress Tracking**: Includes a progress bar (via `tqdm`) for user feedback during processing.
- **Output Files**: Generates categorized output files for valid emails, errors, honeypot domains, and spamtrap domains.

## Requirements

- **Python**: Version 3.6 or higher
- **Dependencies**:
  - `dnspython`: For DNS MX record queries
  - `tqdm`: For progress bar visualization

Install the dependencies using pip:

```bash
pip install dnspython tqdm
```

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/email-domain-filter.git
   cd email-domain-filter
   ```

2. Install the required Python packages:

   ```bash
   pip install dnspython tqdm
   ```

3. Ensure you have a stable internet connection for DNS queries.

## Usage

1. Prepare a text file (e.g., `emails.txt`) containing one email address per line.
2. Run the script:

   ```bash
   python get_safe_mails.py
   ```
3. When prompted, enter the path to your input text file:

   ```
   📂 Enter the path to your .txt email list file: emails.txt
   ```

The script will process the emails and produce the following output files in the current directory:

- **sorted_emails_by_mx.txt**: Valid emails with their corresponding MX records.
- **sorted_emails.txt**: Valid emails without MX records.
- **error_domains.txt**: Emails with invalid formats, invalid domains, or MX record errors.
- **honeypot_domains.txt**: Emails associated with known honeypot domains.
- **spamtrap.txt**: Emails associated with known spamtrap domains or TLDs.

## Example

**Input File (emails.txt)**:

```
user1@example.com
invalid.email@domain
user2@gmail.com
test@10minutemail.com
user3@validcompany.com
```

**Running the Script**:

```bash
python get_safe_mails.py
📂 Enter the path to your .txt email list file: emails.txt
📊 Processing 5 emails to find MX records...
🔍 Fetching MX Records: 100%|██████████| 5/5 [00:03<00:00,  1.67 email/s]
🚫 Spamtraps saved to: spamtrap.txt
✅ Sorting completed! Saved to: sorted_emails_by_mx.txt
⚠️ Honeypots saved to: honeypot_domains.txt
🚨 Errors saved to: error_domains.txt
```

**Output Files**:

- **sorted_emails_by_mx.txt**:

  ```
  user1@example.com,mail.example.com
  user3@validcompany.com,mail.validcompany.com
  ```
- **sorted_emails.txt**:

  ```
  user1@example.com
  user3@validcompany.com
  ```
- **error_domains.txt**:

  ```
  INVALID_FORMAT,invalid.email@domain,
  ```
- **honeypot_domains.txt**:

  ```
  HONEYPOT_DOMAIN,test@10minutemail.com,10minutemail.com
  ```
- **spamtrap.txt**:

  ```
  SPAMTRAP_DOMAIN,user2@gmail.com,gmail.com,google.com
  ```

## Error Handling

- **Encoding Errors**: The script attempts to read the input file with multiple encodings (UTF-8, Latin-1, Windows-1252) and uses a fallback mechanism to replace invalid characters, ensuring robustness.
- **Memory Management**: Processes the file line by line to handle large inputs without exhausting memory.
- **Internet Connectivity**: Checks for internet connectivity before DNS queries and retries if the connection is lost.
- **DNS Issues**: Handles DNS-related errors (e.g., NXDOMAIN, NoAnswer, Timeout) and logs them appropriately.

## Limitations

- Requires an active internet connection for DNS queries.
- Performance depends on the speed of DNS resolution and the number of emails.
- Some legitimate domains may be flagged as spamtraps if they use common mail providers (e.g., Google, Microsoft).
- The list of honeypot and spamtrap domains is static and may need periodic updates.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to suggest improvements, report bugs, or add new features.

## License

# This project is licensed under the MIT License. See the LICENSE file for details.