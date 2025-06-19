import { supabase } from '../lib/supabase';

export interface FileUploadResult {
  url: string;
  path: string;
  size: number;
  type: string;
}

/**
 * Upload file to Supabase Storage
 */
export const uploadFile = async (
  file: File,
  folder: string = 'documents'
): Promise<FileUploadResult> => {
  try {
    // Generate unique filename
    const fileExt = file.name.split('.').pop();
    const fileName = `${Date.now()}-${Math.random().toString(36).substring(2)}.${fileExt}`;
    const filePath = `${folder}/${fileName}`;

    // Upload file to Supabase Storage
    const { data, error } = await supabase.storage
      .from('project-documents')
      .upload(filePath, file, {
        cacheControl: '3600',
        upsert: false
      });

    if (error) {
      throw new Error(`Upload failed: ${error.message}`);
    }

    // Get public URL
    const { data: urlData } = supabase.storage
      .from('project-documents')
      .getPublicUrl(filePath);

    return {
      url: urlData.publicUrl,
      path: filePath,
      size: file.size,
      type: file.type
    };
  } catch (error) {
    console.error('File upload error:', error);
    throw error;
  }
};

/**
 * Delete file from Supabase Storage
 */
export const deleteFile = async (filePath: string): Promise<void> => {
  try {
    const { error } = await supabase.storage
      .from('project-documents')
      .remove([filePath]);

    if (error) {
      throw new Error(`Delete failed: ${error.message}`);
    }
  } catch (error) {
    console.error('File delete error:', error);
    throw error;
  }
};

/**
 * Get signed URL for private file access
 */
export const getSignedUrl = async (
  filePath: string,
  expiresIn: number = 3600
): Promise<string> => {
  try {
    const { data, error } = await supabase.storage
      .from('project-documents')
      .createSignedUrl(filePath, expiresIn);

    if (error) {
      throw new Error(`Signed URL generation failed: ${error.message}`);
    }

    return data.signedUrl;
  } catch (error) {
    console.error('Signed URL error:', error);
    throw error;
  }
};

/**
 * Validate file before upload
 */
export const validateFile = (file: File): { valid: boolean; error?: string } => {
  const maxSize = 10 * 1024 * 1024; // 10MB
  const allowedTypes = [
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain'
  ];

  if (file.size > maxSize) {
    return { valid: false, error: 'File size must be less than 10MB' };
  }

  if (!allowedTypes.includes(file.type)) {
    return { valid: false, error: 'File type not supported. Please upload PDF, DOC, PPT, or XLS files.' };
  }

  return { valid: true };
};

/**
 * Format file size for display
 */
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Get file extension from filename
 */
export const getFileExtension = (filename: string): string => {
  return filename.split('.').pop()?.toLowerCase() || '';
};

/**
 * Get file type icon based on extension
 */
export const getFileTypeIcon = (filename: string): string => {
  const ext = getFileExtension(filename);
  
  switch (ext) {
    case 'pdf':
      return '📄';
    case 'doc':
    case 'docx':
      return '📝';
    case 'ppt':
    case 'pptx':
      return '📊';
    case 'xls':
    case 'xlsx':
      return '📈';
    default:
      return '📁';
  }
};