# Keepsty Backend

This is the backend API for Keepsty running on Google Cloud Platform, connected to the GreenP MongoDB database.

## Deployment to Google Cloud

Make sure you have the Google Cloud SDK installed and configured:

1. Authenticate with Google Cloud:
   ```bash
   gcloud auth login
   ```

2. Set your Google Cloud project:
   ```bash
   gcloud config set project YOUR_PROJECT_ID
   ```

3. Deploy to App Engine:
   ```bash
   gcloud app deploy
   ```

4. View the deployed app:
   ```bash
   gcloud app browse
   ```

## CI/CD Setup with GitHub Actions

To set up continuous deployment from GitHub to Cloud Run:

1. **Create a Service Account in Google Cloud Console**
   - Go to IAM & Admin > Service Accounts
   - Create a new service account (e.g., "github-actions-deploy")
   - Grant it the following roles:
     - Cloud Run Admin
     - Storage Admin
     - Service Account User
   - Create and download a JSON key for this service account

2. **Add Secrets to GitHub Repository**
   - Go to your GitHub repository > Settings > Secrets and variables > Actions
   - Add two new repository secrets:
     - `GCP_PROJECT_ID`: Your Google Cloud project ID (e.g., `spheric-time-457300-s6`)
     - `GCP_SA_KEY`: The entire content of the JSON key file downloaded earlier

3. **Push Code to Repository**
   - The workflow will automatically deploy to Cloud Run when you push to the main/master branch 