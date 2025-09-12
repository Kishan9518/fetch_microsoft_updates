# GitHub Actions CI/CD Pipeline for Windows Patches Database

This repository includes an automated CI/CD pipeline that maintains an up-to-date database of Windows patches from Microsoft Update Catalog.

## Pipeline Overview

The pipeline runs automatically and:
1. **Fetches the latest Windows patches** from Microsoft Update Catalog
2. **Updates the local SQLite database** with new patch information
3. **Commits the updated database** back to the repository
4. **Creates weekly releases** with the database as a downloadable asset

## Pipeline Configuration

### Schedule
- **Daily updates**: Runs every day at 2:00 AM UTC
- **Manual triggers**: Can be manually triggered via GitHub Actions UI

### Pipeline Inputs (Manual Trigger)

When manually triggering the pipeline, you can customize:

- **`max_patches`**: Maximum number of patches to fetch (default: 2000)
- **`method`**: Discovery method (options: `recent`, `critical`, `all`)

### Methods Explained

- **`recent`**: Fetches the most recently released patches
- **`critical`**: Focuses on critical and security updates
- **`all`**: Comprehensive discovery across all available patches

## Database File

The pipeline maintains a file called `windows_patches.db` in the repository root. This SQLite database contains:

- Patch metadata (KB numbers, titles, classifications, descriptions)
- Download URLs and file information
- Architecture and product compatibility details
- Release dates and update history

## Pipeline Features

### 🔄 Automatic Updates
- Checks for existing database and initializes if needed
- Compares before/after statistics
- Only commits when changes are detected
- Includes detailed commit messages with update statistics

### 📊 Monitoring & Reporting
- Database statistics before and after updates
- Recent patches preview in pipeline logs
- Database file size tracking
- Error handling with graceful degradation

### 📦 Artifacts & Releases
- **Artifacts**: Database uploaded as build artifact (30-day retention)
- **Weekly Releases**: Automatic releases every Sunday with database download
- **Release Notes**: Include patch count and usage instructions

### 🛡️ Safety Features
- Rate limiting to respect Microsoft's servers
- Error handling that doesn't fail the entire pipeline
- Git configuration for automated commits
- Database file size monitoring

## Using the Database

### Download Latest Database

#### From Repository
```bash
# The database is tracked in the repository
git clone https://github.com/Kishan9518/fetch_microsoft_updates.git
cd fetch_microsoft_updates
ls -la windows_patches.db
```

#### From Releases
```bash
# Download from latest weekly release
curl -L -o windows_patches.db "https://github.com/Kishan9518/fetch_microsoft_updates/releases/latest/download/windows_patches.db"
```

### Query the Database

```bash
# Search for security updates
python patch_manager.py --db-path windows_patches.db search --classification "Security Updates"

# Find patches for specific KB number
python patch_manager.py --db-path windows_patches.db search --kb-number 5043076

# Get database statistics
python patch_manager.py --db-path windows_patches.db info

# Export to JSON
python patch_manager.py --db-path windows_patches.db export --output patches.json
```

## Manual Pipeline Execution

### Via GitHub Actions UI
1. Go to the **Actions** tab in the repository
2. Select **"Update Windows Patches Database"** workflow
3. Click **"Run workflow"**
4. Adjust parameters if needed:
   - Set `max_patches` (e.g., 500, 1000, 5000)
   - Choose `method` (recent, critical, all)
5. Click **"Run workflow"**

### Monitoring Pipeline Progress

The pipeline provides detailed logging:
- Database initialization status
- Before/after statistics comparison
- Patch discovery progress
- Commit and push confirmation
- Error handling and recovery

## Pipeline Dependencies

### Required GitHub Permissions
- **Contents: write** - For committing database updates
- **Actions: read** - For workflow execution

### External Dependencies
- Microsoft Update Catalog availability
- Network connectivity for patch discovery
- GitHub API for releases (weekly releases)

## Troubleshooting

### Common Issues

**Pipeline fails with DNS blocks**: 
- The pipeline may fail if Microsoft domains are blocked
- This is expected in some sandbox environments
- The pipeline includes error handling to continue gracefully

**Database size grows too large**:
- Monitor database file size in pipeline logs
- Consider archiving older versions
- Adjust `max_patches` parameter for controlled growth

**Rate limiting**:
- Pipeline includes built-in rate limiting
- Microsoft may temporarily block rapid requests
- Pipeline will retry and continue processing

### Debugging

Check pipeline logs for:
- Database statistics before/after updates
- Error messages from patch discovery
- Git commit and push confirmation
- Artifact upload status

## Configuration

The pipeline configuration is in `.github/workflows/update-windows-patches.yml`. Key settings:

```yaml
env:
  DATABASE_NAME: windows_patches.db  # Database filename

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
```

## Security Considerations

- Database file is committed directly to repository
- No sensitive credentials stored in database
- Pipeline uses GitHub's GITHUB_TOKEN for operations
- Rate limiting respects Microsoft's service limits

## Integration Examples

### CI/CD Integration
```yaml
# Use in other workflows
- name: Download patches database
  run: |
    curl -L -o patches.db "https://github.com/Kishan9518/fetch_microsoft_updates/releases/latest/download/windows_patches.db"
    python analysis_script.py --database patches.db
```

### Docker Integration
```dockerfile
# Include in Docker image
RUN curl -L -o /app/patches.db "https://github.com/Kishan9518/fetch_microsoft_updates/releases/latest/download/windows_patches.db"
```

This automated pipeline ensures the Windows patches database stays current without manual intervention, providing a reliable data source for patch management and security analysis workflows.