import os
import re
import sys
import argparse

EXCLUDED_DIRS = {'Templates', '.obsidian'}

def should_validate(filepath, excluded_dirs):
    parts = set(filepath.split(os.sep))
    return not any(ex in parts for ex in excluded_dirs)

def extract_required_headings(filepath):
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()
    # Heading patterns: lines starting with one/more '#'
    headings = []
    for line in lines:
        if re.match(r'^#+\s+', line):
            headings.append(line.strip().lstrip('#').strip())
    return headings

def validate_headings(filepath, required_headings):
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()
    present = [line.strip().lstrip('#').strip() for line in lines if re.match(r'^#+\s+', line)]
    missing = [h for h in required_headings if h not in present]
    return missing

def validate_notes_after_code(filepath):
    with open(filepath, encoding="utf-8") as f:
        lines = [line.rstrip('\n') for line in f.readlines()]
    errors = []
    i = 0
    current_heading = None
    
    while i < len(lines):
        # Track the most recent heading
        if re.match(r'^#+\s+', lines[i]):
            current_heading = lines[i].strip().lstrip('#').strip()
        
        if lines[i].startswith('```'):
            # Search for code block end
            j = i + 1
            while j < len(lines) and not lines[j].startswith('```'):
                j += 1
            if j+1 < len(lines):
                note_line = lines[j+1].strip()
                # Note should not be another heading or code block
                if not note_line or note_line.startswith('#') or note_line.startswith('```'):
                    if current_heading:
                        errors.append(f"❌ {current_heading}")
                    else:
                        errors.append(f"❌ Missing note after code block (no preceding heading)")
            else:
                errors.append(f"Unclosed code block starting at line {i+1}")
            i = j
        i += 1
    return errors

def main():
    parser = argparse.ArgumentParser(description='Validate Markdown structure')
    parser.add_argument('--exclude-path', action='append', help='Path to exclude from validation (can be used multiple times)')
    args = parser.parse_args()
    
    # Build excluded directories set
    excluded_dirs = EXCLUDED_DIRS.copy()
    if args.exclude_path:
        excluded_dirs.update(args.exclude_path)
    
    failed = {}
    for root, dirs, files in os.walk("."):
        # Skip excluded dirs
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        for file in files:
            if file.endswith('.md') and should_validate(os.path.join(root, file), excluded_dirs):
                full_path = os.path.join(root, file)
                required_headings = extract_required_headings(full_path)
                missing_headings = validate_headings(full_path, required_headings)
                note_errors = validate_notes_after_code(full_path)
                if missing_headings or note_errors:
                    failed[full_path] = {
                        "missing_headings": missing_headings,
                        "missing_notes": note_errors
                    }
    if failed:
        print("❌ Validation failed in the following files:")
        for f, issues in failed.items():
            print(f"\nFile: {f}")
            if issues["missing_headings"]:
                print(f"  Missing headings: {issues['missing_headings']}")
            if issues["missing_notes"]:
                print(f" 👀 Missing notes after code blocks: ")
                for note in issues["missing_notes"]:
                    print(f"   {note}")
        sys.exit(1)
    else:
        print("✅ All checked Markdown files meet the requirements.")

if __name__ == '__main__':
    main()
