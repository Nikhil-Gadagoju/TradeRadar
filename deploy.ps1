# TradeRadar Deploy Script
# Usage: .\deploy.ps1 [-message "your commit message"]

param(
    [string]$message = "Update TradeRadar"
)

$PI_USER = "nguser"
$PI_HOST = "192.168.1.75"
$PI_DIR  = "~/stock_analyzer"
$PORT    = "8501"

Write-Host "`n=== TradeRadar Deploy ===" -ForegroundColor Cyan

# 1. Commit any uncommitted changes
$status = git -C $PSScriptRoot status --porcelain
if ($status) {
    Write-Host "`n[1/3] Committing local changes..." -ForegroundColor Yellow
    git -C $PSScriptRoot add -A
    git -C $PSScriptRoot commit -m $message
} else {
    Write-Host "`n[1/3] Nothing to commit, working tree clean." -ForegroundColor Green
}

# 2. Push to GitHub
Write-Host "`n[2/3] Pushing to GitHub..." -ForegroundColor Yellow
git -C $PSScriptRoot push origin master
if ($LASTEXITCODE -ne 0) {
    Write-Host "Push failed. Aborting deploy." -ForegroundColor Red
    exit 1
}
Write-Host "Pushed successfully." -ForegroundColor Green

# 3. SSH into Pi: pull latest + restart app
Write-Host "`n[3/3] Deploying to Pi ($PI_HOST)..." -ForegroundColor Yellow
ssh "${PI_USER}@${PI_HOST}" @"
cd $PI_DIR
git pull origin master
source venv/bin/activate
pip install -r requirements.txt -q
pkill -f 'streamlit run app.py' 2>/dev/null || true
sleep 2
nohup ./venv/bin/streamlit run app.py --server.port $PORT --server.address 0.0.0.0 --server.headless true > streamlit.log 2>&1 &
sleep 3
echo "Running PID: \$(pgrep -f 'streamlit run app.py')"
"@

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=== Deploy complete! App running at http://${PI_HOST}:${PORT} ===" -ForegroundColor Green
} else {
    Write-Host "`nDeploy to Pi failed. Check SSH connection." -ForegroundColor Red
    exit 1
}
