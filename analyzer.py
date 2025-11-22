import os
import subprocess
import glob
import json
import shutil

# Configuration
GHIDRA_HOME = "/home/kamini08/tools/ghidra"
HEADLESS_SCRIPT = "ghidra_script.py"
BIN_DIR = "bin"
PROJECT_DIR = "ghidra_project"
PROJECT_NAME = "permutation_analysis"

def find_headless_analyzer():
    """Finds the analyzeHeadless executable."""
    support_dir = os.path.join(GHIDRA_HOME, "support")
    analyzer = os.path.join(support_dir, "analyzeHeadless")
    if not os.path.exists(analyzer):
        raise FileNotFoundError(f"Could not find analyzeHeadless at {analyzer}")
    return analyzer

def run_analysis():
    analyzer_bin = find_headless_analyzer()
    cwd = os.getcwd()
    script_path = os.path.join(cwd, HEADLESS_SCRIPT)
    
    # Ensure project directory exists (Ghidra will create the project inside)
    if not os.path.exists(PROJECT_DIR):
        os.makedirs(PROJECT_DIR)
        
    binaries = glob.glob(os.path.join(BIN_DIR, "*.elf"))
    
    if not binaries:
        print(f"No binaries found in {BIN_DIR}")
        return

    print(f"Found {len(binaries)} binaries to analyze.")
    
    results = []

    for binary in binaries:
        binary_path = os.path.abspath(binary)
        print(f"Processing {os.path.basename(binary)}...")
        
        # Construct command
        # analyzeHeadless <project_location> <project_name> -import <file> -postScript <script> -deleteProject
        # We use -deleteProject to keep it clean, or we could import all into one project.
        # For independent analysis, importing one by one and not saving is often faster/cleaner 
        # if we just want the script output.
        # However, analyzeHeadless requires a project.
        
        cmd = [
            analyzer_bin,
            os.path.abspath(PROJECT_DIR),
            PROJECT_NAME,
            "-import", binary_path,
            "-postScript", script_path,
            "-deleteProject", # Delete the temporary project after run to save space
            "-overwrite" # Overwrite if exists (though we delete)
        ]
        
        try:
            # Capture stdout to parse the JSON result
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse output for our special tag
            for line in result.stdout.splitlines():
                if line.startswith("JSON_RESULT:"):
                    json_str = line.replace("JSON_RESULT:", "", 1)
                    data = json.loads(json_str)
                    results.append(data)
                    print(f"  -> Functions: {data['functions']}, Instructions: {data['instructions']}")
                    break
            else:
                print("  -> No JSON result found in output.")
                # print(result.stdout) # Debug if needed
                
        except Exception as e:
            print(f"  -> Error: {e}")

    # Save consolidated results
    with open("analysis_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nAnalysis complete. Results saved to analysis_results.json")
    
    # Cleanup project dir if empty/unused
    if os.path.exists(PROJECT_DIR):
        shutil.rmtree(PROJECT_DIR)

if __name__ == "__main__":
    run_analysis()
