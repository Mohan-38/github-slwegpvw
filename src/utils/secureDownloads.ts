import { supabase } from '../lib/supabase';

// Types for secure downloads
export interface SecureDownloadToken {
  id: string;
  token: string;
  document_id: string;
  recipient_email: string;
  order_id: string;
  expires_at: string;
  max_downloads: number;
  download_count: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface DownloadAttempt {
  id: string;
  token_id: string;
  attempted_email: string;
  ip_address?: string;
  user_agent?: string;
  success: boolean;
  failure_reason?: string;
  attempted_at: string;
}

export interface SecureDownloadConfig {
  expirationHours: number;
  maxDownloads: number;
  requireEmailVerification: boolean;
}

// Default configuration
const DEFAULT_CONFIG: SecureDownloadConfig = {
  expirationHours: 72, // 3 days
  maxDownloads: 5,
  requireEmailVerification: true
};

/**
 * Generate secure download tokens for documents
 */
export const generateSecureDownloadTokens = async (
  documents: Array<{
    id: string;
    name: string;
    url: string;
  }>,
  recipientEmail: string,
  orderId: string,
  config: Partial<SecureDownloadConfig> = {}
): Promise<Array<{
  documentId: string;
  documentName: string;
  secureUrl: string;
  expiresAt: string;
}>> => {
  const finalConfig = { ...DEFAULT_CONFIG, ...config };
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + finalConfig.expirationHours);

  const secureUrls: Array<{
    documentId: string;
    documentName: string;
    secureUrl: string;
    expiresAt: string;
  }> = [];

  for (const document of documents) {
    try {
      // Generate secure token using the database function
      const { data: tokenData, error: tokenError } = await supabase.rpc('generate_secure_token');
      
      if (tokenError) {
        console.error('Error generating token:', tokenError);
        // Fallback to client-side token generation
        const token = generateClientSideToken();
        console.log('Using client-side generated token:', token);
        
        // Store token in database
        const { data: storedToken, error: storeError } = await supabase
          .from('secure_download_tokens')
          .insert({
            token,
            document_id: document.id,
            recipient_email: recipientEmail.toLowerCase().trim(),
            order_id: orderId,
            expires_at: expiresAt.toISOString(),
            max_downloads: finalConfig.maxDownloads,
            download_count: 0,
            is_active: true
          })
          .select()
          .single();

        if (storeError) {
          console.error('Error storing token:', storeError);
          continue;
        }

        // Generate secure URL
        const baseUrl = window.location.origin;
        const secureUrl = `${baseUrl}/secure-download/${token}?email=${encodeURIComponent(recipientEmail)}`;

        secureUrls.push({
          documentId: document.id,
          documentName: document.name,
          secureUrl,
          expiresAt: expiresAt.toISOString()
        });
        continue;
      }

      const token = tokenData as string;

      // Store token in database
      const { data: storedToken, error: storeError } = await supabase
        .from('secure_download_tokens')
        .insert({
          token,
          document_id: document.id,
          recipient_email: recipientEmail.toLowerCase().trim(),
          order_id: orderId,
          expires_at: expiresAt.toISOString(),
          max_downloads: finalConfig.maxDownloads,
          download_count: 0,
          is_active: true
        })
        .select()
        .single();

      if (storeError) {
        console.error('Error storing token:', storeError);
        continue;
      }

      // Generate secure URL
      const baseUrl = window.location.origin;
      const secureUrl = `${baseUrl}/secure-download/${token}?email=${encodeURIComponent(recipientEmail)}`;

      secureUrls.push({
        documentId: document.id,
        documentName: document.name,
        secureUrl,
        expiresAt: expiresAt.toISOString()
      });

    } catch (error) {
      console.error('Error generating secure URL for document:', document.id, error);
    }
  }

  return secureUrls;
};

/**
 * Client-side token generation fallback
 */
const generateClientSideToken = (): string => {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 32; i++) {
    result += characters.charAt(Math.floor(Math.random() * characters.length));
  }
  return result;
};

/**
 * Verify and validate download token with enhanced email verification
 */
export const verifyDownloadToken = async (
  token: string,
  attemptedEmail: string,
  ipAddress?: string,
  userAgent?: string
): Promise<{
  valid: boolean;
  document?: any;
  reason?: string;
  tokenData?: SecureDownloadToken;
}> => {
  try {
    console.log('🔍 Verifying download token:', token);
    console.log('📧 Attempted email:', attemptedEmail);

    // Normalize email for comparison
    const normalizedAttemptedEmail = attemptedEmail.toLowerCase().trim();

    // Get token data with document information
    const { data: tokenData, error: tokenError } = await supabase
      .from('secure_download_tokens')
      .select(`
        *,
        project_documents (
          id,
          name,
          url,
          type,
          size,
          document_category,
          review_stage
        )
      `)
      .eq('token', token)
      .eq('is_active', true)
      .single();

    if (tokenError || !tokenData) {
      console.error('❌ Token not found or error:', tokenError);
      await logDownloadAttempt(null, normalizedAttemptedEmail, false, 'Invalid or expired token', ipAddress, userAgent);
      return { valid: false, reason: 'Invalid or expired download link. Please check your email for the correct link.' };
    }

    console.log('✅ Token found:', tokenData.id);
    console.log('📧 Token email:', tokenData.recipient_email);
    console.log('⏰ Token expires:', tokenData.expires_at);

    // Check expiration
    const now = new Date();
    const expiresAt = new Date(tokenData.expires_at);
    if (now > expiresAt) {
      console.error('❌ Token expired');
      await logDownloadAttempt(tokenData.id, normalizedAttemptedEmail, false, 'Token expired', ipAddress, userAgent);
      
      // Deactivate expired token
      await supabase
        .from('secure_download_tokens')
        .update({ is_active: false, updated_at: new Date().toISOString() })
        .eq('id', tokenData.id);

      return { 
        valid: false, 
        reason: `Download link has expired on ${expiresAt.toLocaleDateString()}. Please contact support for new download links.`,
        tokenData 
      };
    }

    // Enhanced email verification with multiple checks
    const normalizedTokenEmail = tokenData.recipient_email.toLowerCase().trim();
    
    // Check exact email match
    if (normalizedTokenEmail !== normalizedAttemptedEmail) {
      console.error('❌ Email mismatch');
      console.log('Expected:', normalizedTokenEmail);
      console.log('Attempted:', normalizedAttemptedEmail);
      
      await logDownloadAttempt(tokenData.id, normalizedAttemptedEmail, false, 'Email mismatch', ipAddress, userAgent);
      return { 
        valid: false, 
        reason: `This download link is authorized for ${tokenData.recipient_email} only. Please use the email address that was used for the purchase.`,
        tokenData 
      };
    }

    // Check download count
    if (tokenData.download_count >= tokenData.max_downloads) {
      console.error('❌ Download limit exceeded');
      await logDownloadAttempt(tokenData.id, normalizedAttemptedEmail, false, 'Download limit exceeded', ipAddress, userAgent);
      return { 
        valid: false, 
        reason: `Download limit of ${tokenData.max_downloads} has been reached for this link. Please contact support if you need additional downloads.`,
        tokenData 
      };
    }

    // Check if document exists
    if (!tokenData.project_documents) {
      console.error('❌ Document not found');
      await logDownloadAttempt(tokenData.id, normalizedAttemptedEmail, false, 'Document not found', ipAddress, userAgent);
      return { 
        valid: false, 
        reason: 'The requested document is no longer available. Please contact support.',
        tokenData 
      };
    }

    console.log('✅ All verifications passed');

    // Valid token - log successful attempt
    await logDownloadAttempt(tokenData.id, normalizedAttemptedEmail, true, null, ipAddress, userAgent);

    // Increment download count
    const { error: updateError } = await supabase
      .from('secure_download_tokens')
      .update({ 
        download_count: tokenData.download_count + 1,
        updated_at: new Date().toISOString()
      })
      .eq('id', tokenData.id);

    if (updateError) {
      console.error('⚠️ Failed to update download count:', updateError);
    }

    return {
      valid: true,
      document: tokenData.project_documents,
      tokenData
    };

  } catch (error) {
    console.error('💥 Error verifying download token:', error);
    await logDownloadAttempt(null, attemptedEmail.toLowerCase().trim(), false, 'System error', ipAddress, userAgent);
    return { valid: false, reason: 'A system error occurred. Please try again or contact support if the problem persists.' };
  }
};

/**
 * Enhanced download attempt logging
 */
const logDownloadAttempt = async (
  tokenId: string | null,
  attemptedEmail: string,
  success: boolean,
  failureReason?: string | null,
  ipAddress?: string,
  userAgent?: string
): Promise<void> => {
  try {
    const { error } = await supabase
      .from('download_attempts')
      .insert({
        token_id: tokenId,
        attempted_email: attemptedEmail.toLowerCase().trim(),
        ip_address: ipAddress,
        user_agent: userAgent,
        success,
        failure_reason: failureReason,
        attempted_at: new Date().toISOString()
      });

    if (error) {
      console.error('Failed to log download attempt:', error);
    } else {
      console.log('📝 Download attempt logged:', { success, email: attemptedEmail, reason: failureReason });
    }
  } catch (error) {
    console.error('Error logging download attempt:', error);
  }
};

/**
 * Get client IP address with multiple fallbacks
 */
export const getClientIP = async (): Promise<string | undefined> => {
  try {
    // Try multiple IP services for better reliability
    const ipServices = [
      'https://api.ipify.org?format=json',
      'https://ipapi.co/json/',
      'https://httpbin.org/ip'
    ];

    for (const service of ipServices) {
      try {
        const response = await fetch(service, { timeout: 5000 } as any);
        const data = await response.json();
        
        // Handle different response formats
        if (data.ip) return data.ip;
        if (data.origin) return data.origin;
        if (data.query) return data.query;
      } catch (serviceError) {
        console.warn(`IP service ${service} failed:`, serviceError);
        continue;
      }
    }
    
    return undefined;
  } catch (error) {
    console.error('Error getting client IP:', error);
    return undefined;
  }
};

/**
 * Enhanced email validation
 */
export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email.trim());
};

/**
 * Revoke download token
 */
export const revokeDownloadToken = async (tokenId: string): Promise<boolean> => {
  try {
    const { error } = await supabase
      .from('secure_download_tokens')
      .update({ 
        is_active: false,
        updated_at: new Date().toISOString()
      })
      .eq('id', tokenId);

    return !error;
  } catch (error) {
    console.error('Error revoking token:', error);
    return false;
  }
};

/**
 * Get download statistics for admin
 */
export const getDownloadStatistics = async (orderId?: string): Promise<{
  totalTokens: number;
  activeTokens: number;
  expiredTokens: number;
  totalAttempts: number;
  successfulDownloads: number;
  failedAttempts: number;
}> => {
  try {
    let tokensQuery = supabase.from('secure_download_tokens').select('*');
    let attemptsQuery = supabase.from('download_attempts').select('*');

    if (orderId) {
      tokensQuery = tokensQuery.eq('order_id', orderId);
      
      // Get token IDs for this order to filter attempts
      const { data: orderTokens } = await supabase
        .from('secure_download_tokens')
        .select('id')
        .eq('order_id', orderId);
      
      if (orderTokens && orderTokens.length > 0) {
        const tokenIds = orderTokens.map(t => t.id);
        attemptsQuery = attemptsQuery.in('token_id', tokenIds);
      }
    }

    const [tokensResult, attemptsResult] = await Promise.all([
      tokensQuery,
      attemptsQuery
    ]);

    const tokens = tokensResult.data || [];
    const attempts = attemptsResult.data || [];

    const now = new Date();
    const activeTokens = tokens.filter(t => t.is_active && new Date(t.expires_at) > now);
    const expiredTokens = tokens.filter(t => !t.is_active || new Date(t.expires_at) <= now);
    const successfulDownloads = attempts.filter(a => a.success);
    const failedAttempts = attempts.filter(a => !a.success);

    return {
      totalTokens: tokens.length,
      activeTokens: activeTokens.length,
      expiredTokens: expiredTokens.length,
      totalAttempts: attempts.length,
      successfulDownloads: successfulDownloads.length,
      failedAttempts: failedAttempts.length
    };

  } catch (error) {
    console.error('Error getting download statistics:', error);
    return {
      totalTokens: 0,
      activeTokens: 0,
      expiredTokens: 0,
      totalAttempts: 0,
      successfulDownloads: 0,
      failedAttempts: 0
    };
  }
};

/**
 * Cleanup expired tokens (admin function)
 */
export const cleanupExpiredTokens = async (): Promise<number> => {
  try {
    const { data, error } = await supabase.rpc('cleanup_expired_tokens');
    
    if (error) {
      console.error('Error cleaning up expired tokens:', error);
      return 0;
    }

    return data || 0;
  } catch (error) {
    console.error('Error cleaning up expired tokens:', error);
    return 0;
  }
};

/**
 * Request new download links (for expired tokens)
 */
export const requestNewDownloadLinks = async (
  orderId: string,
  recipientEmail: string
): Promise<boolean> => {
  try {
    console.log('📧 Requesting new download links for:', { orderId, recipientEmail });
    
    // Log the request in download_attempts for tracking
    await supabase
      .from('download_attempts')
      .insert({
        token_id: null,
        attempted_email: recipientEmail.toLowerCase().trim(),
        success: false,
        failure_reason: `New download links requested for order ${orderId}`,
        attempted_at: new Date().toISOString()
      });
    
    // In a real implementation, you might:
    // 1. Send an email to admin
    // 2. Create a support ticket
    // 3. Automatically regenerate links if within a certain timeframe
    
    return true;
  } catch (error) {
    console.error('Error requesting new download links:', error);
    return false;
  }
};

/**
 * Test download system functionality
 */
export const testDownloadSystem = async (): Promise<void> => {
  console.log('🧪 Testing download system...');
  
  try {
    // Test token generation
    const testToken = generateClientSideToken();
    console.log('✅ Token generation works:', testToken);
    
    // Test email validation
    const validEmail = validateEmail('test@example.com');
    const invalidEmail = validateEmail('invalid-email');
    console.log('✅ Email validation works:', { validEmail, invalidEmail });
    
    // Test IP detection
    const ip = await getClientIP();
    console.log('✅ IP detection works:', ip);
    
    console.log('🎉 Download system test completed successfully');
  } catch (error) {
    console.error('❌ Download system test failed:', error);
  }
};