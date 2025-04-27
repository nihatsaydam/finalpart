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