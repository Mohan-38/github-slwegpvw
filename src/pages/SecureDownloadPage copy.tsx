import React, { useState, useEffect } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { 
  Download, 
  AlertCircle, 
  CheckCircle, 
  Clock, 
  Mail, 
  Shield,
  FileText,
  Loader,
  RefreshCw
} from 'lucide-react';
import { verifyDownloadToken, getClientIP, requestNewDownloadLinks } from '../utils/secureDownloads';
import { formatFileSize } from '../utils/storage';

const SecureDownloadPage = () => {
  const { token } = useParams<{ token: string }>();
  const [searchParams] = useSearchParams();
  const emailParam = searchParams.get('email');

  const [email, setEmail] = useState(emailParam || '');
  const [isVerifying, setIsVerifying] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    valid: boolean;
    document?: any;
    reason?: string;
    tokenData?: any;
  } | null>(null);
  const [clientIP, setClientIP] = useState<string>();
  const [showEmailInput, setShowEmailInput] = useState(!emailParam);
  const [requestingNewLinks, setRequestingNewLinks] = useState(false);

  useEffect(() => {
    // Get client IP for audit trail
    getClientIP().then(setClientIP);
  }, []);

  useEffect(() => {
    // Auto-verify if email is provided in URL
    if (token && emailParam && !verificationResult) {
      handleVerifyAccess();
    }
  }, [token, emailParam]);

  const handleVerifyAccess = async () => {
    if (!token || !email) return;

    setIsVerifying(true);
    setVerificationResult(null);

    try {
      const result = await verifyDownloadToken(
        token,
        email,
        clientIP,
        navigator.userAgent
      );

      setVerificationResult(result);
      
      if (!result.valid) {
        setShowEmailInput(true);
      }
    } catch (error) {
      console.error('Error verifying access:', error);
      setVerificationResult({
        valid: false,
        reason: 'System error occurred. Please try again.'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const handleDownload = async () => {
    if (!verificationResult?.valid || !verificationResult.document) return;

    setIsDownloading(true);
    
    try {
      // Create a temporary link and trigger download
      const link = document.createElement('a');
      link.href = verificationResult.document.url;
      link.download = verificationResult.document.name;
      link.target = '_blank';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (error) {
      console.error('Error downloading file:', error);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleRequestNewLinks = async () => {
    if (!verificationResult?.tokenData?.order_id) return;

    setRequestingNewLinks(true);
    
    try {
      const success = await requestNewDownloadLinks(
        verificationResult.tokenData.order_id,
        email
      );
      
      if (success) {
        alert('Request submitted! You will receive new download links via email within 24 hours.');
      } else {
        alert('Failed to submit request. Please contact support directly.');
      }
    } catch (error) {
      console.error('Error requesting new links:', error);
      alert('Failed to submit request. Please contact support directly.');
    } finally {
      setRequestingNewLinks(false);
    }
  };

  const formatExpirationTime = (expiresAt: string) => {
    const expiry = new Date(expiresAt);
    const now = new Date();
    const diffMs = expiry.getTime() - now.getTime();
    
    if (diffMs <= 0) return 'Expired';
    
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffMinutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
    
    if (diffHours > 0) {
      return `${diffHours}h ${diffMinutes}m remaining`;
    } else {
      return `${diffMinutes}m remaining`;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 pt-24 pb-16">
      <div className="container mx-auto px-4 md:px-6 max-w-2xl">
        <div className="bg-white dark:bg-slate-800 rounded-lg shadow-md p-8">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 dark:bg-blue-900 rounded-full mb-4">
              <Shield className="h-8 w-8 text-blue-600 dark:text-blue-400" />
            </div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-200 mb-2">
              Secure Document Download
            </h1>
            <p className="text-slate-600 dark:text-slate-400">
              Verify your email to access your purchased documents
            </p>
          </div>

          {/* Email Input */}
          {showEmailInput && !verificationResult?.valid && (
            <div className="mb-6">
              <label htmlFor="email" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Email Address
              </label>
              <div className="flex space-x-3">
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="flex-1 px-3 py-2 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:bg-slate-900 dark:text-slate-200"
                  placeholder="Enter your email address"
                  disabled={isVerifying}
                />
                <button
                  onClick={handleVerifyAccess}
                  disabled={!email || isVerifying}
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center"
                >
                  {isVerifying ? (
                    <Loader className="h-4 w-4 animate-spin" />
                  ) : (
                    'Verify'
                  )}
                </button>
              </div>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-2">
                Enter the email address used for your purchase
              </p>
            </div>
          )}

          {/* Verification Result */}
          {verificationResult && (
            <div className="mb-6">
              {verificationResult.valid ? (
                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-6">
                  <div className="flex items-start">
                    <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400 mr-3 mt-0.5" />
                    <div className="flex-1">
                      <h3 className="text-lg font-medium text-green-800 dark:text-green-300 mb-2">
                        Access Verified
                      </h3>
                      
                      {/* Document Info */}
                      <div className="bg-white dark:bg-slate-800 rounded-lg p-4 mb-4">
                        <div className="flex items-center mb-3">
                          <FileText className="h-6 w-6 text-blue-600 dark:text-blue-400 mr-3" />
                          <div>
                            <h4 className="font-medium text-slate-900 dark:text-slate-200">
                              {verificationResult.document.name}
                            </h4>
                            <p className="text-sm text-slate-500 dark:text-slate-400">
                              Size: {formatFileSize(verificationResult.document.size)}
                            </p>
                          </div>
                        </div>
                        
                        <button
                          onClick={handleDownload}
                          disabled={isDownloading}
                          className="w-full flex items-center justify-center px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          {isDownloading ? (
                            <>
                              <Loader className="h-5 w-5 mr-2 animate-spin" />
                              Downloading...
                            </>
                          ) : (
                            <>
                              <Download className="h-5 w-5 mr-2" />
                              Download Document
                            </>
                          )}
                        </button>
                      </div>

                      {/* Download Info */}
                      <div className="text-sm text-green-700 dark:text-green-400 space-y-1">
                        <div className="flex items-center">
                          <Clock className="h-4 w-4 mr-2" />
                          <span>
                            {formatExpirationTime(verificationResult.tokenData.expires_at)}
                          </span>
                        </div>
                        <div className="flex items-center">
                          <Download className="h-4 w-4 mr-2" />
                          <span>
                            Downloads: {verificationResult.tokenData.download_count} / {verificationResult.tokenData.max_downloads}
                          </span>
                        </div>
                        <div className="flex items-center">
                          <Mail className="h-4 w-4 mr-2" />
                          <span>Authorized for: {email}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-6">
                  <div className="flex items-start">
                    <AlertCircle className="h-6 w-6 text-red-600 dark:text-red-400 mr-3 mt-0.5" />
                    <div className="flex-1">
                      <h3 className="text-lg font-medium text-red-800 dark:text-red-300 mb-2">
                        Access Denied
                      </h3>
                      <p className="text-red-700 dark:text-red-400 mb-4">
                        {verificationResult.reason}
                      </p>
                      
                      {/* Action buttons based on error type */}
                      <div className="space-y-3">
                        {verificationResult.reason?.includes('expired') && (
                          <button
                            onClick={handleRequestNewLinks}
                            disabled={requestingNewLinks}
                            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            {requestingNewLinks ? (
                              <>
                                <Loader className="h-4 w-4 mr-2 animate-spin" />
                                Requesting...
                              </>
                            ) : (
                              <>
                                <RefreshCw className="h-4 w-4 mr-2" />
                                Request New Links
                              </>
                            )}
                          </button>
                        )}
                        
                        {verificationResult.reason?.includes('email') && (
                          <button
                            onClick={() => {
                              setShowEmailInput(true);
                              setVerificationResult(null);
                              setEmail('');
                            }}
                            className="flex items-center px-4 py-2 bg-slate-600 text-white rounded-lg hover:bg-slate-700"
                          >
                            <Mail className="h-4 w-4 mr-2" />
                            Try Different Email
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Security Notice */}
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
            <div className="flex items-start">
              <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400 mr-3 mt-0.5" />
              <div className="text-sm text-blue-800 dark:text-blue-300">
                <h4 className="font-medium mb-1">Security Notice</h4>
                <ul className="space-y-1 text-blue-700 dark:text-blue-400">
                  <li>• Download links are time-limited and email-specific</li>
                  <li>• Links cannot be shared or forwarded to other users</li>
                  <li>• All download attempts are logged for security</li>
                  <li>• Contact support if you need assistance</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Support Contact */}
          <div className="mt-6 text-center">
            <p className="text-sm text-slate-600 dark:text-slate-400">
              Need help? Contact us at{' '}
              <a 
                href="mailto:mohanselenophile@gmail.com" 
                className="text-blue-600 dark:text-blue-400 hover:underline"
              >
                mohanselenophile@gmail.com
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SecureDownloadPage;