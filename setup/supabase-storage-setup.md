# Supabase Storage Setup

Storage buckets must be created manually in the Supabase Dashboard before running `fresh-install-complete.sql`.

## Required Bucket: `message-attachments`

**Purpose**: Stores encrypted file attachments for messages (24-hour retention).

### Setup Steps

1. Go to your Supabase Dashboard
2. Navigate to **Storage** in the left sidebar
3. Click **New bucket**
4. Configure:
   - **Name**: `message-attachments`
   - **Public bucket**: Unchecked (private)
   - **File size limit**: 1MB
5. Click **Create bucket**

### RLS Policies

The storage bucket RLS policies are included in `fresh-install-complete.sql` and will be applied automatically when you run that script. No additional SQL is needed.

## Verification

After setup, the application logs:
```
[AttachmentService] ✓ Storage bucket 'message-attachments' is accessible
```

If the bucket is missing:
```
[AttachmentService] ✗ Storage bucket 'message-attachments' not found - file attachments disabled
```

## File Retention

Files auto-delete after 24 hours via the `cleanup_expired_attachments()` function in the database.
