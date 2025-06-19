import React, { useState, useEffect } from 'react';
import { 
  User, 
  Bell, 
  Lock, 
  Palette, 
  Mail, 
  Phone, 
  Globe, 
  Moon, 
  Sun,
  CheckCircle,
  Save,
  AlertCircle
} from 'lucide-react';
import AdminLayout from '../../components/admin/AdminLayout';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { supabase } from '../../lib/supabase';

const AdminSettingsPage = () => {
  const { user, updateProfile } = useAuth();
  const { theme, setTheme } = useTheme();
  const [activeTab, setActiveTab] = useState('profile');
  const [showSuccess, setShowSuccess] = useState(false);
  const [showError, setShowError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  
  // Profile Settings
  const [profileData, setProfileData] = useState({
    name: user?.name || '',
    email: user?.email || '',
    phone: user?.phone || '',
    website: user?.website || '',
    bio: user?.bio || ''
  });
  
  // Notification Settings
  const [notifications, setNotifications] = useState({
    emailNotifications: true,
    projectUpdates: true,
    newInquiries: true,
    orderAlerts: true,
    marketingEmails: false
  });
  
  // Security Settings
  const [securityData, setSecurityData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  // Email Settings
  const [emailSettings, setEmailSettings] = useState({
    newEmail: '',
    confirmEmail: ''
  });
  
  // Appearance Settings
  const [appearance, setAppearance] = useState({
    theme: theme,
    fontSize: 'medium',
    compactMode: false,
    animationsEnabled: true
  });

  // Load user data
  useEffect(() => {
    if (user) {
      setProfileData({
        name: user.name || '',
        email: user.email || '',
        phone: user.phone || '',
        website: user.website || '',
        bio: user.bio || ''
      });
    }
  }, [user]);

  // Update theme when appearance changes
  useEffect(() => {
    setTheme(appearance.theme as 'light' | 'dark');
  }, [appearance.theme, setTheme]);
  
  const handleProfileSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setShowError(null);
    
    try {
      // Update user profile in Supabase
      const { error } = await supabase.auth.updateUser({
        data: {
          name: profileData.name,
          phone: profileData.phone,
          website: profileData.website,
          bio: profileData.bio
        }
      });

      if (error) throw error;

      // Update local context
      await updateProfile(profileData);
      
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 3000);
    } catch (error) {
      setShowError(error instanceof Error ? error.message : 'Failed to update profile');
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleNotificationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setShowError(null);
    
    try {
      // Update notification preferences in Supabase
      const { error } = await supabase.auth.updateUser({
        data: { notification_preferences: notifications }
      });

      if (error) throw error;
      
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 3000);
    } catch (error) {
      setShowError(error instanceof Error ? error.message : 'Failed to update notification preferences');
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleSecuritySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setShowError(null);
    
    try {
      if (securityData.newPassword !== securityData.confirmPassword) {
        throw new Error('Passwords do not match');
      }

      // Update password in Supabase
      const { error } = await supabase.auth.updateUser({
        password: securityData.newPassword
      });

      if (error) throw error;
      
      setShowSuccess(true);
      setSecurityData({ currentPassword: '', newPassword: '', confirmPassword: '' });
      setTimeout(() => setShowSuccess(false), 3000);
    } catch (error) {
      setShowError(error instanceof Error ? error.message : 'Failed to update password');
    } finally {
      setIsLoading(false);
    }
  };

  const handleEmailChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setShowError(null);
    
    try {
      if (emailSettings.newEmail !== emailSettings.confirmEmail) {
        throw new Error('Email addresses do not match');
      }

      // Update email in Supabase
      const { error } = await supabase.auth.updateUser({
        email: emailSettings.newEmail
      });

      if (error) throw error;

      // Update local context
      await updateProfile({ ...profileData, email: emailSettings.newEmail });
      
      setShowSuccess(true);
      setEmailSettings({ newEmail: '', confirmEmail: '' });
      setTimeout(() => setShowSuccess(false), 3000);
    } catch (error) {
      setShowError(error instanceof Error ? error.message : 'Failed to update email');
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleAppearanceSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setShowError(null);
    
    try {
      // Update appearance settings in Supabase
      const { error } = await supabase.auth.updateUser({
        data: { appearance_settings: appearance }
      });

      if (error) throw error;
      
      setShowSuccess(true);
      setTimeout(() => setShowSuccess(false), 3000);
    } catch (error) {
      setShowError(error instanceof Error ? error.message : 'Failed to update appearance settings');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AdminLayout>
      <div className="px-4 sm:px-6 py-8">
        <div className="max-w-4xl mx-auto">
          <div className="mb-8">
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Settings</h1>
            <p className="text-slate-500 dark:text-slate-400">Manage your account settings and preferences.</p>
          </div>
          
          {/* Success Message */}
          {showSuccess && (
            <div className="mb-6 bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-300 p-4 rounded-lg flex items-center">
              <CheckCircle className="h-5 w-5 mr-2" />
              Settings updated successfully!
            </div>
          )}

          {/* Error Message */}
          {showError && (
            <div className="mb-6 bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-300 p-4 rounded-lg flex items-center">
              <AlertCircle className="h-5 w-5 mr-2" />
              {showError}
            </div>
          )}
          
          <div className="bg-white dark:bg-slate-800 rounded-lg shadow-md overflow-hidden">
            <div className="flex border-b border-slate-200 dark:border-slate-700">
              <button
                onClick={() => setActiveTab('profile')}
                className={`px-6 py-3 text-sm font-medium ${
                  activeTab === 'profile'
                    ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <User className="h-4 w-4 inline-block mr-2" />
                Profile
              </button>
              
              <button
                onClick={() => setActiveTab('notifications')}
                className={`px-6 py-3 text-sm font-medium ${
                  activeTab === 'notifications'
                    ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <Bell className="h-4 w-4 inline-block mr-2" />
                Notifications
              </button>
              
              <button
                onClick={() => setActiveTab('security')}
                className={`px-6 py-3 text-sm font-medium ${
                  activeTab === 'security'
                    ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <Lock className="h-4 w-4 inline-block mr-2" />
                Security
              </button>
              
              <button
                onClick={() => setActiveTab('appearance')}
                className={`px-6 py-3 text-sm font-medium ${
                  activeTab === 'appearance'
                    ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <Palette className="h-4 w-4 inline-block mr-2" />
                Appearance
              </button>
            </div>
            
            <div className="p-6">
              {/* Profile Settings */}
              {activeTab === 'profile' && (
                <form onSubmit={handleProfileSubmit} className="space-y-6">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">
                      Full Name
                    </label>
                    <input
                      type="text"
                      value={profileData.name}
                      onChange={(e) => setProfileData({ ...profileData, name: e.target.value })}
                      className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">
                      Email Address
                    </label>
                    <div className="flex items-center">
                      <Mail className="h-5 w-5 text-slate-400" />
                      <input
                        type="email"
                        value={profileData.email}
                        onChange={(e) => setProfileData({ ...profileData, email: e.target.value })}
                        className="flex-1 ml-2 px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                        disabled
                      />
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">
                      Phone Number
                    </label>
                    <div className="flex items-center">
                      <Phone className="h-5 w-5 text-slate-400" />
                      <input
                        type="tel"
                        value={profileData.phone}
                        onChange={(e) => setProfileData({ ...profileData, phone: e.target.value })}
                        className="flex-1 ml-2 px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                      />
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">
                      Website
                    </label>
                    <div className="flex items-center">
                      <Globe className="h-5 w-5 text-slate-400" />
                      <input
                        type="url"
                        value={profileData.website}
                        onChange={(e) => setProfileData({ ...profileData, website: e.target.value })}
                        className="flex-1 ml-2 px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                      />
                    </div>
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">
                      Bio
                    </label>
                    <textarea
                      value={profileData.bio}
                      onChange={(e) => setProfileData({ ...profileData, bio: e.target.value })}
                      rows={4}
                      className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                    ></textarea>
                  </div>
                  
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={isLoading}
                      className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    >
                      {isLoading ? (
                        <>
                          <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          Saving...
                        </>
                      ) : (
                        <>
                          <Save className="h-4 w-4 mr-2" />
                          Save Changes
                        </>
                      )}
                    </button>
                  </div>
                </form>
              )}
              
              {/* Notification Settings */}
              {activeTab === 'notifications' && (
                <form onSubmit={handleNotificationSubmit} className="space-y-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-medium text-slate-900 dark:text-white">Email Notifications</h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400">Receive notifications via email</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={notifications.emailNotifications}
                          onChange={(e) => setNotifications({ ...notifications, emailNotifications: e.target.checked })}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-slate-200 dark:bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                      </label>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-medium text-slate-900 dark:text-white">Project Updates</h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400">Get notified about project changes</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={notifications.projectUpdates}
                          onChange={(e) => setNotifications({ ...notifications, projectUpdates: e.target.checked })}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-slate-200 dark:bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                      </label>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-medium text-slate-900 dark:text-white">New Inquiries</h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400">Get notified about new client inquiries</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={notifications.newInquiries}
                          onChange={(e) => setNotifications({ ...notifications, newInquiries: e.target.checked })}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-slate-200 dark:bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                      </label>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-medium text-slate-900 dark:text-white">Order Alerts</h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400">Get notified about new orders</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={notifications.orderAlerts}
                          onChange={(e) => setNotifications({ ...notifications, orderAlerts: e.target.checked })}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-slate-200 dark:bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                      </label>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-medium text-slate-900 dark:text-white">Marketing Emails</h3>
                        <p className="text-sm text-slate-500 dark:text-slate-400">Receive marketing and promotional emails</p>
                      </div>
                      <label className="relative inline-flex items-center cursor-pointer">
                        <input
                          type="checkbox"
                          checked={notifications.marketingEmails}
                          onChange={(e) => setNotifications({ ...notifications, marketingEmails: e.target.checked })}
                          className="sr-only peer"
                        />
                        <div className="w-11 h-6 bg-slate-200 dark:bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                      </label>
                    </div>
                  </div>
                  
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={isLoading}
                      className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    >
                      {isLoading ? (
                        <>
                          <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          Saving...
                        </>
                      ) : (
                        <>
                          <Save className="h-4 w-4 mr-2" />
                          Save Preferences
                        </>
                      )}
                    </button>
                  </div>
                </form>
              )}
              
              {/* Security Settings */}
              {activeTab === 'security' && (
                <div className="space-y-6">
                  {/* Password Change Form */}
                  <form onSubmit={handleSecuritySubmit} className="space-y-6">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Change Password</h3>
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">
                        Current Password
                      </label>
                      <input
                        type="password"
                        value={securityData.currentPassword}
                        onChange={(e) => setSecurityData({ ...securityData, currentPassword: e.target.value })}
                        className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                      />
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">
                        New Password
                      </label>
                      <input
                        type="password"
                        value={securityData.newPassword}
                        onChange={(e) => setSecurityData({ ...securityData, newPassword: e.target.value })}
                        className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                      />
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">
                        Confirm New Password
                      </label>
                      <input
                        type="password"
                        value={securityData.confirmPassword}
                        onChange={(e) => setSecurityData({ ...securityData, confirmPassword: e.target.value })}
                        className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                      />
                    </div>
                    
                    <div className="flex justify-end">
                      <button
                        type="submit"
                        disabled={isLoading}
                        className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                      >
                        {isLoading ? (
                          <>
                            <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Updating...
                          </>
                        ) : (
                          <>
                            <Save className="h-4 w-4 mr-2" />
                            Update Password
                          </>
                        )}
                      </button>
                    </div>
                  </form>

                  <hr className="border-slate-200 dark:border-slate-700" />

                  {/* Email Change Form */}
                  <form onSubmit={handleEmailChange} className="space-y-6">
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Change Email</h3>
                    
                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        Current Email
                      </label>
                      <input
                        type="email"
                        value={user?.email || ''}
                        disabled
                        className="w-full px-3 py-2 bg-slate-100 dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md text-slate-900 dark:text-slate-300"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        New Email
                      </label>
                      <input
                        type="email"
                        value={emailSettings.newEmail}
                        onChange={(e) => setEmailSettings({ ...emailSettings, newEmail: e.target.value })}
                        className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                        Confirm New Email
                      </label>
                      <input
                        type="email"
                        value={emailSettings.confirmEmail}
                        onChange={(e) => setEmailSettings({ ...emailSettings, confirmEmail: e.target.value })}
                        className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                        required
                      />
                    </div>

                    <div className="flex justify-end">
                      <button
                        type="submit"
                        disabled={isLoading}
                        className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                      >
                        {isLoading ? (
                          <>
                            <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Updating...
                          </>
                        ) : (
                          <>
                            <Save className="h-4 w-4 mr-2" />
                            Update Email
                          </>
                        )}
                      </button>
                    </div>
                  </form>
                </div>
              )}
              
              {/* Appearance Settings */}
              {activeTab === 'appearance' && (
                <form onSubmit={handleAppearanceSubmit} className="space-y-6">
                  {/* Theme Selection */}
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">Theme</h3>
                    <div className="flex space-x-4">
                      {['light', 'dark'].map((themeOption) => (
                        <label key={themeOption} className="flex items-center">
                          <input
                            type="radio"
                            name="theme"
                            value={themeOption}
                            checked={appearance.theme === themeOption}
                            onChange={(e) => setAppearance({ ...appearance, theme: e.target.value })}
                            className="sr-only"
                          />
                          <div
                            className={`p-3 rounded-lg flex items-center cursor-pointer ${
                              appearance.theme === themeOption
                                ? 'bg-blue-50 dark:bg-blue-900 text-blue-600 dark:text-blue-400 ring-2 ring-blue-600 dark:ring-blue-400'
                                : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600'
                            }`}
                          >
                            {themeOption === 'light' ? <Sun className="h-5 w-5 mr-2" /> : <Moon className="h-5 w-5 mr-2" />}
                            {themeOption.charAt(0).toUpperCase() + themeOption.slice(1)}
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>
              
                  {/* Font Size (readonly, Medium) */}
                  <div>
                    <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-2">Font Size</h3>
                    <select
                      value={appearance.fontSize}
                      onChange={(e) => setAppearance({ ...appearance, fontSize: e.target.value })}
                      className="w-full px-3 py-2 bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 dark:text-white"
                    >
                      <option value="medium">Medium</option>
                    </select>
                  </div>
              
                  {/* Compact Mode */}
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-medium text-slate-900 dark:text-white">Compact Mode</h3>
                      <p className="text-sm text-slate-500 dark:text-slate-400">Use compact layout for dense information</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={appearance.compactMode}
                        onChange={(e) => setAppearance({ ...appearance, compactMode: e.target.checked })}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-slate-200 dark:bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>
              
                  {/* Animations Toggle */}
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-medium text-slate-900 dark:text-white">Enable Animations</h3>
                      <p className="text-sm text-slate-500 dark:text-slate-400">Show animations and transitions</p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        checked={appearance.animationsEnabled}
                        onChange={(e) => setAppearance({ ...appearance, animationsEnabled: e.target.checked })}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-slate-200 dark:bg-slate-700 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                    </label>
                  </div>
              
                  {/* Submit Button */}
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={isLoading}
                      className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                    >
                      {isLoading ? (
                        <>
                          <svg className="animate-spin -ml-1 mr-2 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                          </svg>
                          Saving...
                        </>
                      ) : (
                        <>
                          <Save className="h-4 w-4 mr-2" />
                          Save Preferences
                        </>
                      )}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
};

export default AdminSettingsPage;