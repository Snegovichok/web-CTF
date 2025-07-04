import os
import subprocess

def main():
    subprocess.run(["rm", "-r", "download"], cwd="checkers/web")
    subprocess.run(["rm", "-r", "instance"], cwd="services/web")
    subprocess.run(["rm", "-r", "user_uploads"], cwd="services/web")
    subprocess.run(["rm", "-r", "stolen_priv_mes"], cwd="sploits/web")
    subprocess.run(["rm", "-r", "stolen_files"], cwd="sploits/web")
    
if __name__ == "__main__":
    main()

