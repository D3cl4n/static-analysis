import argparse
import analyzer

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", help="binary file to analyze", type=str, required=True)
    args = parser.parse_args()

    analyzer.search(args.binary)

if __name__ == '__main__':
    main()