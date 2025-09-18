===============================================================================
                        BITCOIN LOCAL SCANNER v1.0
                           User Manual & Guide
===============================================================================

TABLE OF CONTENTS:
1. Overview
2. How the Program Works
3. System Requirements
4. Installation & Setup
5. Configuration Guide
6. Running the Scanner
7. Understanding Output
8. Troubleshooting
9. Performance Tips
10. Security & Legal Notes

===============================================================================
1. OVERVIEW
===============================================================================

Bitcoin Local Scanner is a high-performance cryptocurrency wallet discovery tool
that generates random seed phrases, derives wallet addresses, and checks their
balances against a local Bitcoin blockchain. This tool is designed for
educational purposes and legitimate wallet recovery scenarios.

Key Features:
- Multi-threaded CPU processing for maximum speed
- Local blockchain scanning (no internet required)
- Multiple address format support (Legacy, SegWit, Native SegWit)
- Real-time progress dashboard
- Configurable settings via config.txt
- Duplicate prevention database
- Comprehensive result logging

===============================================================================
2. HOW THE PROGRAM WORKS
===============================================================================

The Bitcoin Local Scanner operates through a sophisticated multi-step process:

STEP 1: SEED PHRASE GENERATION
------------------------------
The program generates cryptographically secure 12-word mnemonic seed phrases
using the BIP39 standard. Each seed phrase represents a unique wallet:

- Uses secure random number generation
- Follows BIP39 wordlist specification
- Generates 128-bit entropy (12 words)
- Validates checksum for each seed phrase
- Tracks generated seeds to prevent duplicates

Example seed phrase: "abandon ability able about above absent absorb abstract absurd abuse access accident"

STEP 2: WALLET ADDRESS DERIVATION
----------------------------------
From each seed phrase, the program derives multiple Bitcoin addresses using
standard derivation paths:

2.1 LEGACY ADDRESSES (P2PKH) - BIP44 Path: m/44'/0'/0'/0/0
    - Format: Starts with '1' (e.g., 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa)
    - Most compatible format
    - Higher transaction fees

2.2 SEGWIT ADDRESSES (P2SH-P2WPKH) - BIP49 Path: m/49'/0'/0'/0/0
    - Format: Starts with '3' (e.g., 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy)
    - Backward compatible
    - Lower transaction fees than Legacy

2.3 NATIVE SEGWIT ADDRESSES (P2WPKH) - BIP84 Path: m/84'/0'/0'/0/0
    - Format: Starts with 'bc1' (e.g., bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)
    - Lowest transaction fees
    - Most modern format

The derivation process:
1. Seed phrase → Master private key (BIP32)
2. Master key → Extended private key (derivation path)
3. Private key → Public key (elliptic curve cryptography)
4. Public key → Address (hashing + encoding)

STEP 3: BLOCKCHAIN BALANCE CHECKING
------------------------------------
For each derived address, the program checks the local Bitcoin blockchain:

3.1 LOCAL BLOCKCHAIN SCANNING
    - Reads Bitcoin Core blockchain files directly
    - Scans transaction outputs (UTXOs)
    - Calculates current balance for each address
    - No internet connection required
    - Faster than API calls

3.2 BALANCE CALCULATION
    - Sums all unspent transaction outputs
    - Converts satoshis to Bitcoin (1 BTC = 100,000,000 satoshis)
    - Tracks both received and spent amounts
    - Provides accurate current balance

STEP 4: RESULT PROCESSING
-------------------------
The program processes and logs all findings:

- Wallets with balance → Saved to output file
- Empty wallets → Counted but not saved (configurable)
- Statistics → Real-time dashboard display
- Progress → Continuous monitoring and reporting

===============================================================================
3. SYSTEM REQUIREMENTS
===============================================================================

MINIMUM REQUIREMENTS:
- Windows 10 or later (64-bit)
- 4 GB RAM (8 GB recommended)
- 2 CPU cores (4+ cores recommended)
- 500 GB free disk space (for Bitcoin blockchain)
- Bitcoin Core installed and synchronized

RECOMMENDED SPECIFICATIONS:
- Windows 11 (64-bit)
- 16 GB RAM or more
- 8+ CPU cores (Intel i7/i9 or AMD Ryzen 7/9)
- 1 TB SSD storage
- High-speed internet (for initial blockchain sync)

===============================================================================
4. INSTALLATION & SETUP
===============================================================================

STEP 1: BITCOIN CORE SETUP
---------------------------
1. Download Bitcoin Core from: https://bitcoin.org/en/download
2. Install Bitcoin Core
3. Run Bitcoin Core and wait for full blockchain synchronization
   (This may take several days and requires ~500GB of storage)
4. Note the blockchain data directory location:
   - Windows default: C:\Users\%USERNAME%\AppData\Roaming\Bitcoin\blocks
   - Custom installations may vary

STEP 2: SCANNER SETUP
----------------------
1. Extract all files to a folder (e.g., C:\BitcoinScanner\)
2. Ensure these files are present:
   - BitcoinLocalScanner.exe (main executable)
   - config.txt (configuration file)
   - README.txt (this file)

3. Edit config.txt to match your system (see Configuration Guide below)

===============================================================================
5. CONFIGURATION GUIDE
===============================================================================

The config.txt file controls all scanner behavior. Edit this file before
running the scanner:

GENERAL SETTINGS:
-----------------
num_threads = 8
  Description: Number of CPU threads to use for scanning
  Recommended: Set to your CPU core count or slightly less
  Example: For 8-core CPU, use 6-8 threads

target_wallets = 0
  Description: Number of wallets to scan (0 = infinite)
  Example: Set to 1000000 to scan exactly 1 million wallets

multiple_addresses = true
  Description: Check all address types (Legacy, SegWit, Native SegWit)
  true = More comprehensive but slower
  false = Legacy addresses only (faster)

BLOCKCHAIN SETTINGS:
--------------------
bitcoin_blockchain_path = C:\Bitcoin\blocks
  Description: Path to Bitcoin Core blockchain data
  CRITICAL: This must point to your Bitcoin Core 'blocks' folder
  Common paths:
  - C:\Users\%USERNAME%\AppData\Roaming\Bitcoin\blocks
  - D:\Bitcoin\blocks (custom installation)
  - Leave empty to use online APIs (slower, requires internet)

OUTPUT SETTINGS:
----------------
output_file = bitcoin_wallets_with_balance.txt
  Description: File to save discovered wallets with balance
  Format: Each line contains seed phrase, address, and balance

database_file = checked_seeds.db
  Description: SQLite database to track checked seed phrases
  Prevents duplicate checking across multiple runs

PERFORMANCE SETTINGS:
---------------------
dashboard_enabled = true
  Description: Show real-time progress dashboard
  true = Display statistics and progress
  false = Run silently (slightly faster)

dashboard_update_interval = 1
  Description: Dashboard refresh rate in seconds
  Lower values = more responsive but higher CPU usage

ADVANCED SETTINGS:
------------------
scan_timeout = 0
  Description: Maximum scan time in seconds (0 = no limit)
  Example: 3600 = stop after 1 hour

memory_optimization = false
  Description: Enable memory-saving mode
  true = Lower memory usage but slightly slower

verbose_logging = false
  Description: Enable detailed logging
  true = More information but slower performance

===============================================================================
6. RUNNING THE SCANNER
===============================================================================

STEP 1: PREPARE YOUR SYSTEM
----------------------------
1. Ensure Bitcoin Core is fully synchronized
2. Close Bitcoin Core application (scanner needs exclusive access)
3. Edit config.txt with your blockchain path
4. Ensure sufficient disk space for results

STEP 2: START THE SCANNER
-------------------------
1. Double-click BitcoinLocalScanner.exe
2. The program will:
   - Display startup banner
   - Load configuration from config.txt
   - Show current settings
   - Initialize seed database
   - Begin scanning process

STEP 3: MONITOR PROGRESS
------------------------
The real-time dashboard shows:
- Total wallets checked
- Wallets with balance found
- Empty wallets count
- Current scanning rate (wallets/hour)
- Per-thread statistics
- Elapsed time

STEP 4: STOP THE SCANNER
------------------------
To stop the scanner:
- Press Ctrl+C in the console window
- Close the console window
- The program will save progress and display final statistics

===============================================================================
7. UNDERSTANDING OUTPUT
===============================================================================

OUTPUT FILE FORMAT:
-------------------
The output file (bitcoin_wallets_with_balance.txt) contains discovered wallets:

Format: SEED_PHRASE | ADDRESS | BALANCE_BTC | ADDRESS_TYPE | TIMESTAMP

Example:
"abandon ability able about above absent absorb abstract absurd abuse access accident" | 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa | 0.00123456 | P2PKH | 2024-01-15 14:30:22

Field Descriptions:
- SEED_PHRASE: 12-word mnemonic that generates the wallet
- ADDRESS: Bitcoin address with balance
- BALANCE_BTC: Current balance in Bitcoin
- ADDRESS_TYPE: P2PKH (Legacy), P2SH (SegWit), or P2WPKH (Native SegWit)
- TIMESTAMP: When the wallet was discovered

DASHBOARD STATISTICS:
---------------------
Real-time display shows:
- Wallets Checked: Total number of seed phrases tested
- Found with Balance: Number of wallets containing Bitcoin
- Empty Wallets: Number of wallets with zero balance
- Rate: Current scanning speed (wallets per hour)
- Thread Stats: Performance per CPU thread

DATABASE FILES:
---------------
- checked_seeds.db: SQLite database tracking processed seed phrases
- Prevents duplicate work across multiple runs
- Can be deleted to start fresh (loses progress tracking)

===============================================================================
8. TROUBLESHOOTING
===============================================================================

COMMON ISSUES AND SOLUTIONS:

ISSUE: "Blockchain directory not found"
SOLUTION:
1. Verify Bitcoin Core is installed and synchronized
2. Check blockchain path in config.txt
3. Ensure path points to 'blocks' folder, not Bitcoin folder
4. Try running as administrator

ISSUE: "Permission denied" or "Access denied"
SOLUTION:
1. Close Bitcoin Core application
2. Run scanner as administrator
3. Check folder permissions
4. Ensure antivirus isn't blocking access

ISSUE: Slow scanning speed
SOLUTION:
1. Increase num_threads in config.txt
2. Set multiple_addresses = false for faster scanning
3. Disable dashboard_enabled for slight speed boost
4. Ensure SSD storage for blockchain data
5. Close other applications to free CPU/RAM

ISSUE: High memory usage
SOLUTION:
1. Set memory_optimization = true in config.txt
2. Reduce num_threads
3. Close other applications
4. Add more RAM to system

ISSUE: Scanner crashes or freezes
SOLUTION:
1. Check system resources (CPU, RAM, disk space)
2. Reduce num_threads
3. Ensure blockchain data isn't corrupted
4. Run memory diagnostic tools
5. Update system drivers

===============================================================================
9. PERFORMANCE TIPS
===============================================================================

OPTIMIZATION STRATEGIES:

CPU OPTIMIZATION:
- Set num_threads to 75-100% of your CPU cores
- Monitor CPU temperature during extended runs
- Ensure adequate cooling for sustained performance

STORAGE OPTIMIZATION:
- Use SSD for blockchain data (much faster than HDD)
- Ensure sufficient free space (20%+ recommended)
- Defragment HDD if using traditional storage

MEMORY OPTIMIZATION:
- Close unnecessary applications
- Set memory_optimization = true for large scans
- Monitor RAM usage during operation

NETWORK OPTIMIZATION:
- Use local blockchain (no internet required during scanning)
- Ensure stable connection for initial Bitcoin Core sync

SCANNING STRATEGY:
- Start with multiple_addresses = false for initial testing
- Use target_wallets for controlled test runs
- Run overnight for extended scanning sessions

EXPECTED PERFORMANCE:
- Modern 8-core CPU: 50,000-100,000 wallets/hour
- High-end 16-core CPU: 100,000-200,000 wallets/hour
- Performance varies based on address types and system specs

===============================================================================
10. SECURITY & LEGAL NOTES
===============================================================================

SECURITY CONSIDERATIONS:

DATA PROTECTION:
- Keep discovered wallets secure and private
- Use strong passwords for system access
- Consider encrypted storage for sensitive results
- Regularly backup important findings

SYSTEM SECURITY:
- Run from trusted, secure computer
- Keep antivirus software updated
- Avoid running on shared or public computers
- Monitor system for unusual activity

LEGAL COMPLIANCE:

IMPORTANT DISCLAIMERS:
- This tool is for educational and legitimate recovery purposes only
- Users are responsible for compliance with local laws
- Respect others' property and privacy
- Do not use for unauthorized access to others' wallets

LEGITIMATE USE CASES:
- Personal wallet recovery
- Educational cryptocurrency research
- Security testing with proper authorization
- Academic blockchain analysis

ETHICAL GUIDELINES:
- Only scan for wallets you own or have permission to recover
- Respect intellectual property and privacy rights
- Follow responsible disclosure for security research
- Consider the environmental impact of computational resources

===============================================================================

For technical support or questions, please refer to the documentation or
community resources. This software is provided as-is without warranty.

Version: 1.0
Last Updated: September 15th 2025

===============================================================================
