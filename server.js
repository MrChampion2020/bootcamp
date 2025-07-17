const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const dotenv = require('dotenv')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const helmet = require('helmet')
const morgan = require('morgan')
const http = require("http")
const https = require("https")
const socketIo = require("socket.io")
const cloudinary = require('cloudinary').v2;
const nodemailer = require('nodemailer');
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
dotenv.config()

const app = express()

// Security middleware
app.use(helmet())
app.use(morgan('combined'))

const corsOptions = {
  origin: '*',
  credentials: true,
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
  allowedHeaders: 'Origin,X-Requested-With,Content-Type,Accept,Authorization',
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true }))

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err))

// Setup nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Admin Schema
const adminSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['super_admin', 'admin', 'moderator'],
    default: 'admin'
  },
  permissions: [{
    type: String,
    enum: ['manage_streams', 'manage_users', 'manage_comments', 'view_analytics', 'manage_admins']
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: { 
    type: Date, 
    default: Date.now 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
})

// Enhanced Stream Schema
const streamSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  streamUrl: {
    type: String,
    required: true,
    trim: true
  },
  streamType: {
    type: String,
    enum: ['youtube', 'facebook', 'castr', 'vimeo', 'twitch', 'other'],
    default: 'other'
  },
  thumbnail: {
    type: String,
    trim: true
  },
  scheduledDate: {
    type: Date
  },
  duration: {
    type: Number, // in minutes
    default: 0
  },
  isLive: {
    type: Boolean,
    default: false
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isFeatured: {
    type: Boolean,
    default: false
  },
  tags: [{
    type: String,
    trim: true
  }],
  viewCount: {
    type: Number,
    default: 0
  },
  likeCount: {
    type: Number,
    default: 0
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin',
    required: true
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: { 
    type: Date, 
    default: Date.now 
  },
  reactions: {
    amen: { type: Number, default: 0 },
    praise: { type: Number, default: 0 },
    fire: { type: Number, default: 0 },
    heart: { type: Number, default: 0 },
    sad: { type: Number, default: 0 }
  }
})

// Enhanced Comment Schema
const commentSchema = new mongoose.Schema({
  streamId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Stream',
    required: true
  },
  userName: {
    type: String,
    required: true,
    trim: true
  },
  userEmail: {
    type: String,
    required: true,
    trim: true
  },
  userAvatar: {
    type: String,
    trim: true
  },
  content: {
    type: String,
    required: true,
    trim: true,
    maxlength: 500
  },
  reactions: {
    amen: { type: Number, default: 0 },
    praise: { type: Number, default: 0 },
    fire: { type: Number, default: 0 },
    heart: { type: Number, default: 0 },
    sad: { type: Number, default: 0 }
  },
  isModerated: {
    type: Boolean,
    default: false
  },
  isSpam: {
    type: Boolean,
    default: false
  },
  ipAddress: {
    type: String
  },
  userAgent: {
    type: String
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
})

// Enhanced User Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    unique: true
  },
  phone: {
    type: String,
    required: true,
    trim: true
  },
  location: {
    type: String,
    required: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  avatar: {
    type: String,
    trim: true
  },
  audienceSize: {
    type: String,
    default: "1"
  },
  expectations: {
    type: String,
    trim: true
  },
  preferences: {
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true }
    },
    language: {
      type: String,
      default: 'en'
    },
    timezone: {
      type: String,
      default: 'UTC'
    }
  },
  stats: {
    totalWatched: { type: Number, default: 0 },
    totalComments: { type: Number, default: 0 },
    totalReactions: { type: Number, default: 0 }
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  isBlocked: {
    type: Boolean,
    default: false
  },
  lastLogin: { 
    type: Date, 
    default: Date.now 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
})

// Testimony Schema
const testimonySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  testimony: {
    type: String,
    required: true,
    trim: true
  },
  category: {
    type: String,
    enum: ['healing', 'deliverance', 'provision', 'relationship', 'other'],
    default: 'other'
  },
  isApproved: {
    type: Boolean,
    default: false
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin'
  },
  approvedAt: {
    type: Date
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
})

// Contact/Support Schema
const contactSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true
  },
  subject: {
    type: String,
    required: true,
    trim: true
  },
  message: {
    type: String,
    required: true,
    trim: true
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  status: {
    type: String,
    enum: ['new', 'in_progress', 'resolved', 'closed'],
    default: 'new'
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin'
  },
  response: {
    type: String,
    trim: true
  },
  respondedAt: {
    type: Date
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
})

// Analytics Schema
const analyticsSchema = new mongoose.Schema({
  streamId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Stream'
  },
  type: {
    type: String,
    enum: ['view', 'comment', 'reaction', 'user_registration', 'testimony_submission', 'prayer_request', 'chat_message'],
    required: true
  },
  data: {
    type: mongoose.Schema.Types.Mixed
  },
  timestamp: { 
    type: Date, 
    default: Date.now 
  }
})

// Prayer Request Schema
const prayerRequestSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true
  },
  subject: {
    type: String,
    required: true,
    trim: true
  },
  prayerRequest: {
    type: String,
    required: true,
    trim: true
  },
  category: {
    type: String,
    enum: ['healing', 'deliverance', 'provision', 'relationship', 'family', 'work', 'other'],
    default: 'other'
  },
  isConfidential: {
    type: Boolean,
    default: false
  },
  isAnswered: {
    type: Boolean,
    default: false
  },
  isPublic: {
    type: Boolean,
    default: false
  },
  status: {
    type: String,
    enum: ['pending', 'praying', 'answered', 'closed'],
    default: 'pending'
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Admin'
  },
  response: {
    type: String,
    trim: true
  },
  respondedAt: {
    type: Date
  },
  ipAddress: {
    type: String
  },
  userAgent: {
    type: String
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
})

// Chat Message Schema
const chatMessageSchema = new mongoose.Schema({
  streamId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Stream'
  },
  userName: {
    type: String,
    required: true,
    trim: true
  },
  userEmail: {
    type: String,
    required: true,
    trim: true
  },
  message: {
    type: String,
    required: true,
    trim: true,
    maxlength: 500
  },
  messageType: {
    type: String,
    enum: ['chat', 'prayer'],
    default: 'chat'
  },
  reactions: {
    amen: { type: Number, default: 0 },
    praise: { type: Number, default: 0 },
    fire: { type: Number, default: 0 },
    heart: { type: Number, default: 0 },
    sad: { type: Number, default: 0 }
  },
  isModerated: {
    type: Boolean,
    default: false
  },
  isSpam: {
    type: Boolean,
    default: false
  },
  ipAddress: {
    type: String
  },
  userAgent: {
    type: String
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
})

// Notification Schema
const notificationSchema = new mongoose.Schema({
  recipient: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  message: {
    type: String,
    required: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['stream_start', 'comment_reply', 'testimony_approved', 'general'],
    default: 'general'
  },
  isRead: {
    type: Boolean,
    default: false
  },
  readAt: {
    type: Date
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
})

// Create models
const Admin = mongoose.model("Admin", adminSchema)
const Stream = mongoose.model("Stream", streamSchema)
const Comment = mongoose.model("Comment", commentSchema)
const User = mongoose.model("User", userSchema)
const Testimony = mongoose.model("Testimony", testimonySchema)
const Contact = mongoose.model("Contact", contactSchema)
const Analytics = mongoose.model("Analytics", analyticsSchema)
const Notification = mongoose.model("Notification", notificationSchema)
const PrayerRequest = mongoose.model("PrayerRequest", prayerRequestSchema)
const ChatMessage = mongoose.model("ChatMessage", chatMessageSchema)

// General Chat Schema (for quick, non-stream-specific chats)
const generalChatSchema = new mongoose.Schema({
  participants: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: String,
    email: String,
    isAdmin: { type: Boolean, default: false }
  }],
  messages: [{
    sender: {
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      name: String,
      email: String,
      isAdmin: { type: Boolean, default: false }
    },
    message: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const GeneralChat = mongoose.model('GeneralChat', generalChatSchema);

// Event Schema
const eventSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String, trim: true },
  startDate: { type: Date, required: true },
  endDate: { type: Date },
  location: { type: String, trim: true },
  imageUrl: { type: String, trim: true },
  videoUrl: { type: String, trim: true }, // New: video URL
  videoDuration: { type: Number, default: 0 }, // New: video duration in seconds
  category: { type: String, enum: ['children', 'teens', 'main'], required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});
const Event = mongoose.model('Event', eventSchema);

// Enhanced stream type detection and URL processing
const getStreamType = (url) => {
  if (!url) return 'other';
  
  const lowerUrl = url.toLowerCase();
  
  if (lowerUrl.includes('youtube.com') || lowerUrl.includes('youtu.be')) {
    return 'youtube';
  } else if (lowerUrl.includes('facebook.com') || lowerUrl.includes('fb.watch')) {
    return 'facebook';
  } else if (lowerUrl.includes('castr.io') || lowerUrl.includes('castr.com')) {
    return 'castr';
  } else if (lowerUrl.includes('vimeo.com')) {
    return 'vimeo';
  } else if (lowerUrl.includes('twitch.tv')) {
    return 'twitch';
  }
  
  return 'other';
};

const generateEmbedUrl = (url, streamType) => {
  if (!url) return url;
  
  switch (streamType) {
    case 'youtube':
      // Handle various YouTube URL formats
      let videoId = '';
      if (url.includes('youtube.com/watch?v=')) {
        videoId = url.split('v=')[1]?.split('&')[0];
      } else if (url.includes('youtube.com/live/')) {
        videoId = url.split('/live/')[1]?.split('?')[0];
      } else if (url.includes('youtu.be/')) {
        videoId = url.split('youtu.be/')[1]?.split('?')[0];
      }
      return videoId ? `https://www.youtube.com/embed/${videoId}?autoplay=1&mute=0` : url;
      
    case 'facebook':
      // Handle Facebook video URLs
      if (url.includes('facebook.com/plugins/video.php')) {
        return url;
      } else if (url.includes('facebook.com/')) {
        // Convert Facebook post URL to embed URL
        const postId = url.split('facebook.com/')[1]?.split('/')[1];
        return postId ? `https://www.facebook.com/plugins/video.php?href=https%3A%2F%2Fwww.facebook.com%2F${postId}&show_text=false&width=500&height=281&appId` : url;
      }
      return url;
      
    case 'castr':
      // Handle Castr URLs
      if (url.includes('castr.io/player/')) {
        return url;
      } else if (url.includes('castr.io/')) {
        const streamId = url.split('castr.io/')[1]?.split('/')[0];
        return streamId ? `https://app.castr.io/player/${streamId}?autoplay=1` : url;
      }
      return url;
      
    case 'vimeo':
      // Handle Vimeo URLs
      const vimeoId = url.match(/vimeo\.com\/(\d+)/)?.[1];
      return vimeoId ? `https://player.vimeo.com/video/${vimeoId}?autoplay=1` : url;
      
    case 'twitch':
      // Handle Twitch URLs
      const twitchChannel = url.match(/twitch\.tv\/(\w+)/)?.[1];
      return twitchChannel ? `https://player.twitch.tv/?channel=${twitchChannel}&parent=localhost` : url;
      
    default:
      return url;
  }
};

const validateStreamUrl = (url, streamType) => {
  if (!url) return { valid: false, error: 'URL is required' };
  
  try {
    new URL(url);
  } catch {
    return { valid: false, error: 'Invalid URL format' };
  }
  
  switch (streamType) {
    case 'youtube':
      if (!url.includes('youtube.com') && !url.includes('youtu.be')) {
        return { valid: false, error: 'Invalid YouTube URL' };
      }
      break;
    case 'facebook':
      if (!url.includes('facebook.com') && !url.includes('fb.watch')) {
        return { valid: false, error: 'Invalid Facebook URL' };
      }
      break;
    case 'castr':
      if (!url.includes('castr.io') && !url.includes('castr.com')) {
        return { valid: false, error: 'Invalid Castr URL' };
      }
      break;
  }
  
  return { valid: true };
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
      return res.status(401).json({ message: "Access token required" })
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const admin = await Admin.findById(decoded.adminId)
    
    if (!admin || !admin.isActive) {
      return res.status(401).json({ message: "Invalid or inactive admin account" })
    }

    req.admin = admin
    next()
  } catch (error) {
    return res.status(403).json({ message: "Invalid token" })
  }
}

const requirePermission = (permission) => {
  return (req, res, next) => {
    if (!req.admin.permissions.includes(permission)) {
      return res.status(403).json({ message: "Insufficient permissions" })
    }
    next()
  }
}

// Helper: Send notification (DB + email)
async function sendNotification({ recipient, title, message, type = 'general', email, ip, userAgent, location }) {
  // Save to DB
  await new Notification({ recipient, title, message, type }).save();
  // Send email if email is provided
  if (email && process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    let details = '';
    if (ip) details += `IP Address: ${ip}\n`;
    if (userAgent) details += `Browser: ${userAgent}\n`;
    if (location) details += `Location: ${location}\n`;
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: `[CEIBZ1] ${title}`,
      text: `${message}\n\n${details}`
    };
    try {
      await transporter.sendMail(mailOptions);
    } catch (err) {
      console.error('Error sending email:', err);
    }
  }
}

// Admin Authentication Routes

// Admin login
app.post("/api/admin/login", async (req, res) => {
  try {
    const { username, password } = req.body
    
    const admin = await Admin.findOne({ username, isActive: true })
    if (!admin) {
      return res.status(401).json({ message: "Invalid credentials" })
    }
    
    const isValidPassword = await bcrypt.compare(password, admin.password)
    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid credentials" })
    }
    
    // Update last login
    admin.lastLogin = Date.now()
    await admin.save()
    
    // Generate JWT token
    const token = jwt.sign(
      { adminId: admin._id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    )
    
    res.status(200).json({
      message: "Login successful",
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        role: admin.role,
        permissions: admin.permissions
      }
    })
  } catch (error) {
    console.error("Error logging in admin:", error)
    res.status(500).json({ message: "Error logging in" })
  }
})

// Create initial admin (first time setup)
app.post("/api/admin/setup", async (req, res) => {
  try {
    const adminCount = await Admin.countDocuments()
    if (adminCount > 0) {
      return res.status(400).json({ message: "Admin already exists" })
    }
    
    const { username, email, password } = req.body
    
    const hashedPassword = await bcrypt.hash(password, 12)
    
    const admin = new Admin({
      username,
      email,
      password: hashedPassword,
      role: 'super_admin',
      permissions: ['manage_streams', 'manage_users', 'manage_comments', 'view_analytics', 'manage_admins']
    })
    
    await admin.save()
    
    res.status(201).json({
      message: "Admin account created successfully",
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
        role: admin.role
      }
    })
  } catch (error) {
    console.error("Error creating admin:", error)
    res.status(500).json({ message: "Error creating admin account" })
  }
})

// Admin Routes (Protected)

// Get admin dashboard stats
app.get("/api/admin/dashboard", authenticateToken, async (req, res) => {
  try {
    const [
      totalStreams,
      activeStreams,
      totalUsers,
      totalComments,
      totalTestimonies,
      pendingTestimonies,
      pendingContacts,
      todayUsers,
      todayComments
    ] = await Promise.all([
      Stream.countDocuments(),
      Stream.countDocuments({ isActive: true }),
      User.countDocuments(),
      Comment.countDocuments(),
      Testimony.countDocuments(),
      Testimony.countDocuments({ isApproved: false }),
      Contact.countDocuments({ status: 'new' }),
      User.countDocuments({ createdAt: { $gte: new Date().setHours(0, 0, 0, 0) } }),
      Comment.countDocuments({ createdAt: { $gte: new Date().setHours(0, 0, 0, 0) } })
    ])
    
    // Get recent activity
    const recentStreams = await Stream.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('createdBy', 'username')
    
    const recentComments = await Comment.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('streamId', 'title')
    
    const recentUsers = await User.find()
      .sort({ createdAt: -1 })
      .limit(5)
    
    res.status(200).json({
      stats: {
        totalStreams,
        activeStreams,
        totalUsers,
        totalComments,
        totalTestimonies,
        pendingTestimonies,
        pendingContacts,
        todayUsers,
        todayComments
      },
      recentActivity: {
        streams: recentStreams,
        comments: recentComments,
        users: recentUsers
      }
    })
  } catch (error) {
    console.error("Error fetching dashboard stats:", error)
    res.status(500).json({ message: "Error fetching dashboard stats" })
  }
})

// Stream Management Routes

// Get all streams with pagination and filters
app.get("/api/admin/streams", authenticateToken, requirePermission('manage_streams'), async (req, res) => {
  try {
    const { page = 1, limit = 10, status, type, search } = req.query
    
    const filter = {}
    if (status) filter.isActive = status === 'active'
    if (type) filter.streamType = type
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ]
    }
    
    const streams = await Stream.find(filter)
      .populate('createdBy', 'username')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
    
    const total = await Stream.countDocuments(filter)
    
    res.status(200).json({
      streams,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    })
  } catch (error) {
    console.error("Error fetching streams:", error)
    res.status(500).json({ message: "Error fetching streams" })
  }
})

// Add new stream
app.post("/api/admin/stream", authenticateToken, requirePermission('manage_streams'), async (req, res) => {
  try {
    const { title, description, streamUrl, scheduledDate, tags, isFeatured } = req.body
    
    if (!title || !streamUrl) {
      return res.status(400).json({ message: "Title and stream URL are required" })
    }

    const streamType = getStreamType(streamUrl)
    const embedUrl = generateEmbedUrl(streamUrl, streamType)
    
    const newStream = new Stream({
      title,
      description,
      streamUrl,
      embedUrl,
      streamType,
      scheduledDate: scheduledDate ? new Date(scheduledDate) : null,
      tags: tags || [],
      isFeatured: isFeatured || false,
      createdBy: req.admin._id
    })
    
    await newStream.save()
    
    // Log analytics
    await new Analytics({
      type: 'stream_created',
      data: { streamId: newStream._id, createdBy: req.admin._id }
    }).save()
    
    res.status(201).json({
      message: "Stream added successfully",
      stream: newStream
    })
  } catch (error) {
    console.error("Error adding stream:", error)
    res.status(500).json({ message: "Error adding stream" })
  }
})

// Update stream
app.put("/api/admin/stream/:id", authenticateToken, requirePermission('manage_streams'), async (req, res) => {
  try {
    const { id } = req.params
    const updateData = req.body
    
    if (updateData.streamUrl) {
      updateData.streamType = getStreamType(updateData.streamUrl)
      updateData.embedUrl = generateEmbedUrl(updateData.streamUrl, updateData.streamType)
    }
    
    updateData.updatedAt = Date.now()
    
    const updatedStream = await Stream.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    ).populate('createdBy', 'username')
    
    if (!updatedStream) {
      return res.status(404).json({ message: "Stream not found" })
    }
    
    res.status(200).json({
      message: "Stream updated successfully",
      stream: updatedStream
    })
  } catch (error) {
    console.error("Error updating stream:", error)
    res.status(500).json({ message: "Error updating stream" })
  }
})

// Delete stream
app.delete("/api/admin/stream/:id", authenticateToken, requirePermission('manage_streams'), async (req, res) => {
  try {
    const { id } = req.params
    
    const deletedStream = await Stream.findByIdAndDelete(id)
    
    if (!deletedStream) {
      return res.status(404).json({ message: "Stream not found" })
    }
    
    // Delete associated data
    await Promise.all([
      Comment.deleteMany({ streamId: id }),
      Analytics.deleteMany({ streamId: id })
    ])
    
    res.status(200).json({
      message: "Stream deleted successfully",
      stream: deletedStream
    })
  } catch (error) {
    console.error("Error deleting stream:", error)
    res.status(500).json({ message: "Error deleting stream" })
  }
})

// Toggle stream live status
app.patch("/api/admin/stream/:id/toggle-live", authenticateToken, requirePermission('manage_streams'), async (req, res) => {
  try {
    const { id } = req.params
    
    const stream = await Stream.findById(id)
    if (!stream) {
      return res.status(404).json({ message: "Stream not found" })
    }
    
    stream.isLive = !stream.isLive
    stream.updatedAt = Date.now()
    await stream.save()
    
    res.status(200).json({
      message: `Stream ${stream.isLive ? 'started' : 'stopped'} successfully`,
      stream
    })
  } catch (error) {
    console.error("Error toggling stream status:", error)
    res.status(500).json({ message: "Error toggling stream status" })
  }
})

// User Management Routes

// Get all users with pagination and filters
app.get("/api/admin/users", authenticateToken, requirePermission('manage_users'), async (req, res) => {
  try {
    const { page = 1, limit = 10, status, search } = req.query
    
    const filter = {}
    if (status === 'blocked') filter.isBlocked = true
    if (status === 'active') filter.isBlocked = false
    if (search) {
      filter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } }
      ]
    }
    
    const users = await User.find(filter)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
    
    const total = await User.countDocuments(filter)
    
    res.status(200).json({
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    })
  } catch (error) {
    console.error("Error fetching users:", error)
    res.status(500).json({ message: "Error fetching users" })
  }
})

// Block/Unblock user
app.patch("/api/admin/user/:id/toggle-block", authenticateToken, requirePermission('manage_users'), async (req, res) => {
  try {
    const { id } = req.params
    
    const user = await User.findById(id)
    if (!user) {
      return res.status(404).json({ message: "User not found" })
    }
    
    user.isBlocked = !user.isBlocked
    await user.save()
    
    res.status(200).json({
      message: `User ${user.isBlocked ? 'blocked' : 'unblocked'} successfully`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isBlocked: user.isBlocked
      }
    })
  } catch (error) {
    console.error("Error toggling user block status:", error)
    res.status(500).json({ message: "Error toggling user block status" })
  }
})

// Comment Management Routes

// Get all comments with pagination and filters
app.get("/api/admin/comments", authenticateToken, requirePermission('manage_comments'), async (req, res) => {
  try {
    const { page = 1, limit = 10, streamId, status, search } = req.query
    
    const filter = {}
    if (streamId) filter.streamId = streamId
    if (status === 'moderated') filter.isModerated = true
    if (status === 'spam') filter.isSpam = true
    if (search) {
      filter.$or = [
        { content: { $regex: search, $options: 'i' } },
        { userName: { $regex: search, $options: 'i' } },
        { userEmail: { $regex: search, $options: 'i' } }
      ]
    }
    
    const comments = await Comment.find(filter)
      .populate('streamId', 'title')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
    
    const total = await Comment.countDocuments(filter)
    
    res.status(200).json({
      comments,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    })
  } catch (error) {
    console.error("Error fetching comments:", error)
    res.status(500).json({ message: "Error fetching comments" })
  }
})

// Moderate comment
app.patch("/api/admin/comment/:id/moderate", authenticateToken, requirePermission('manage_comments'), async (req, res) => {
  try {
    const { id } = req.params
    const { action } = req.body // 'approve', 'reject', 'mark_spam'
    
    const comment = await Comment.findById(id)
    if (!comment) {
      return res.status(404).json({ message: "Comment not found" })
    }
    
    switch (action) {
      case 'approve':
        comment.isModerated = true
        comment.isSpam = false
        break
      case 'reject':
        comment.isModerated = true
        comment.isSpam = false
        break
      case 'mark_spam':
        comment.isSpam = true
        break
      default:
        return res.status(400).json({ message: "Invalid action" })
    }
    
    await comment.save()
    
    res.status(200).json({
      message: `Comment ${action}ed successfully`,
      comment
    })
  } catch (error) {
    console.error("Error moderating comment:", error)
    res.status(500).json({ message: "Error moderating comment" })
  }
})

// Delete comment
app.delete("/api/admin/comment/:id", authenticateToken, requirePermission('manage_comments'), async (req, res) => {
  try {
    const { id } = req.params
    
    const deletedComment = await Comment.findByIdAndDelete(id)
    
    if (!deletedComment) {
      return res.status(404).json({ message: "Comment not found" })
    }
    
    res.status(200).json({
      message: "Comment deleted successfully",
      comment: deletedComment
    })
  } catch (error) {
    console.error("Error deleting comment:", error)
    res.status(500).json({ message: "Error deleting comment" })
  }
})

// Testimony Management Routes

// Get all testimonies
app.get("/api/admin/testimonies", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, category } = req.query
    
    const filter = {}
    if (status === 'pending') filter.isApproved = false
    if (status === 'approved') filter.isApproved = true
    if (category) filter.category = category
    
    const testimonies = await Testimony.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
    
    const total = await Testimony.countDocuments(filter)
    
    res.status(200).json({
      testimonies,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    })
  } catch (error) {
    console.error("Error fetching testimonies:", error)
    res.status(500).json({ message: "Error fetching testimonies" })
  }
})

// Approve/Reject testimony
app.patch("/api/admin/testimony/:id/approve", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const { isApproved, isPublic } = req.body
    
    const testimony = await Testimony.findById(id)
    if (!testimony) {
      return res.status(404).json({ message: "Testimony not found" })
    }
    
    testimony.isApproved = isApproved
    testimony.isPublic = isPublic
    testimony.approvedBy = req.admin._id
    testimony.approvedAt = Date.now()
    
    await testimony.save()
    
    res.status(200).json({
      message: `Testimony ${isApproved ? 'approved' : 'rejected'} successfully`,
      testimony
    })
  } catch (error) {
    console.error("Error approving testimony:", error)
    res.status(500).json({ message: "Error approving testimony" })
  }
})

// Contact Management Routes

// Get all contacts
app.get("/api/admin/contacts", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, priority } = req.query
    
    const filter = {}
    if (status) filter.status = status
    if (priority) filter.priority = priority
    
    const contacts = await Contact.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
    
    const total = await Contact.countDocuments(filter)
    
    res.status(200).json({
      contacts,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    })
  } catch (error) {
    console.error("Error fetching contacts:", error)
    res.status(500).json({ message: "Error fetching contacts" })
  }
})

// Update contact status
app.patch("/api/admin/contact/:id/status", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const { status, response, assignedTo } = req.body
    
    const contact = await Contact.findById(id)
    if (!contact) {
      return res.status(404).json({ message: "Contact not found" })
    }
    
    contact.status = status
    if (response) {
      contact.response = response
      contact.respondedAt = Date.now()
    }
    if (assignedTo) contact.assignedTo = assignedTo
    
    await contact.save()
    
    res.status(200).json({
      message: "Contact status updated successfully",
      contact
    })
  } catch (error) {
    console.error("Error updating contact status:", error)
    res.status(500).json({ message: "Error updating contact status" })
  }
})

// Analytics Routes

// Get analytics data
app.get("/api/admin/analytics", authenticateToken, requirePermission('view_analytics'), async (req, res) => {
  try {
    const { period = '7d' } = req.query
    
    let startDate
    switch (period) {
      case '24h':
        startDate = new Date(Date.now() - 24 * 60 * 60 * 1000)
        break
      case '7d':
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
        break
      case '30d':
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        break
      default:
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
    }
    
    const [
      userRegistrations,
      comments,
      testimonies,
      streamViews,
      prayerRequests,
      chatMessages
    ] = await Promise.all([
      User.countDocuments({ createdAt: { $gte: startDate } }),
      Comment.countDocuments({ createdAt: { $gte: startDate } }),
      Testimony.countDocuments({ createdAt: { $gte: startDate } }),
      Analytics.countDocuments({ 
        type: 'view',
        timestamp: { $gte: startDate }
      }),
      PrayerRequest.countDocuments({ createdAt: { $gte: startDate } }),
      ChatMessage.countDocuments({ createdAt: { $gte: startDate } })
    ])
    
    // Get top streams
    const topStreams = await Stream.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      { $lookup: { from: 'comments', localField: '_id', foreignField: 'streamId', as: 'comments' } },
      { $addFields: { commentCount: { $size: '$comments' } } },
      { $sort: { commentCount: -1 } },
      { $limit: 5 }
    ])
    
    res.status(200).json({
      period,
      stats: {
        userRegistrations,
        comments,
        testimonies,
        streamViews,
        prayerRequests,
        chatMessages
      },
      topStreams
    })
  } catch (error) {
    console.error("Error fetching analytics:", error)
    res.status(500).json({ message: "Error fetching analytics" })
  }
})

// Prayer Request Management Routes

// Get all prayer requests
app.get("/api/admin/prayer-requests", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, category } = req.query
    
    const filter = {}
    if (status) filter.status = status
    if (category) filter.category = category
    
    const prayerRequests = await PrayerRequest.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
    
    const total = await PrayerRequest.countDocuments(filter)
    
    res.status(200).json({
      prayerRequests,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    })
  } catch (error) {
    console.error("Error fetching prayer requests:", error)
    res.status(500).json({ message: "Error fetching prayer requests" })
  }
})

// Update prayer request status
app.patch("/api/admin/prayer-request/:id/status", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const { status, response, assignedTo, isAnswered } = req.body
    
    const prayerRequest = await PrayerRequest.findById(id)
    if (!prayerRequest) {
      return res.status(404).json({ message: "Prayer request not found" })
    }
    
    prayerRequest.status = status
    if (response) {
      prayerRequest.response = response
      prayerRequest.respondedAt = Date.now()
    }
    if (assignedTo) prayerRequest.assignedTo = assignedTo
    if (isAnswered !== undefined) prayerRequest.isAnswered = isAnswered
    
    await prayerRequest.save()
    
    res.status(200).json({
      message: "Prayer request status updated successfully",
      prayerRequest
    })
  } catch (error) {
    console.error("Error updating prayer request status:", error)
    res.status(500).json({ message: "Error updating prayer request status" })
  }
})

// Chat Message Management Routes

// Get all chat messages
app.get("/api/admin/chat-messages", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, messageType, streamId, isModerated } = req.query
    
    const filter = {}
    if (messageType) filter.messageType = messageType
    if (streamId) filter.streamId = streamId
    if (isModerated !== undefined) filter.isModerated = isModerated === 'true'
    
    const chatMessages = await ChatMessage.find(filter)
      .populate('streamId', 'title')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
    
    const total = await ChatMessage.countDocuments(filter)
    
    res.status(200).json({
      chatMessages,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      total
    })
  } catch (error) {
    console.error("Error fetching chat messages:", error)
    res.status(500).json({ message: "Error fetching chat messages" })
  }
})

// Moderate chat message
app.patch("/api/admin/chat-message/:id/moderate", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const { isModerated, isSpam } = req.body
    
    const chatMessage = await ChatMessage.findById(id)
    if (!chatMessage) {
      return res.status(404).json({ message: "Chat message not found" })
    }
    
    if (isModerated !== undefined) chatMessage.isModerated = isModerated
    if (isSpam !== undefined) chatMessage.isSpam = isSpam
    
    await chatMessage.save()
    
    res.status(200).json({
      message: "Chat message moderated successfully",
      chatMessage
    })
  } catch (error) {
    console.error("Error moderating chat message:", error)
    res.status(500).json({ message: "Error moderating chat message" })
  }
})

// Delete chat message
app.delete("/api/admin/chat-message/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    
    const chatMessage = await ChatMessage.findByIdAndDelete(id)
    if (!chatMessage) {
      return res.status(404).json({ message: "Chat message not found" })
    }
    
    res.status(200).json({
      message: "Chat message deleted successfully"
    })
  } catch (error) {
    console.error("Error deleting chat message:", error)
    res.status(500).json({ message: "Error deleting chat message" })
  }
})

// Public Routes (No Authentication Required)

// Get active streams
app.get("/api/streams/active", async (req, res) => {
  try {
    const streams = await Stream.find({ isActive: true, isLive: true })
      .sort({ isFeatured: -1, createdAt: -1 })
      .limit(10)
    
    res.status(200).json(streams)
  } catch (error) {
    console.error("Error fetching active streams:", error)
    res.status(500).json({ message: "Error fetching streams" })
  }
})

// Get stream by ID
app.get("/api/stream/:id", async (req, res) => {
  try {
    const { id } = req.params
    
    const stream = await Stream.findById(id)
    if (!stream) {
      return res.status(404).json({ message: "Stream not found" })
    }
    
    // Increment view count
    stream.viewCount += 1
    await stream.save()
    
    // Log analytics
    await new Analytics({
      streamId: id,
      type: 'view',
      data: { ip: req.ip, userAgent: req.get('User-Agent') }
    }).save()
    
    res.status(200).json(stream)
  } catch (error) {
    console.error("Error fetching stream:", error)
    res.status(500).json({ message: "Error fetching stream" })
  }
})

// Add stream like endpoint
app.post("/api/stream/:id/like", async (req, res) => {
  try {
    const { id } = req.params;
    const stream = await Stream.findById(id);
    if (!stream) {
      return res.status(404).json({ message: "Stream not found" });
    }
    stream.likeCount = (stream.likeCount || 0) + 1;
    await stream.save();
    res.status(200).json({ likeCount: stream.likeCount });
  } catch (error) {
    console.error("Error liking stream:", error);
    res.status(500).json({ message: "Error liking stream" });
  }
});

// User registration
app.post("/api/user/register", async (req, res) => {
  try {
    const userData = req.body
    
    // Check if user already exists
    const existingUser = await User.findOne({ email: userData.email })
    if (existingUser) {
      return res.status(400).json({ message: "User with this email already exists" })
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(userData.password, 12)
    userData.password = hashedPassword
    
    const newUser = new User(userData)
    await newUser.save()

    // Log analytics
    await new Analytics({
      type: 'user_registration',
      data: { userId: newUser._id, location: userData.location }
    }).save()

    res.status(201).json({
      message: "User registered successfully",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email
      }
    })
  } catch (error) {
    console.error("Error registering user:", error)
    res.status(500).json({ message: "Error registering user" })
  }
})

// User login
app.post("/api/user/login", async (req, res) => {
  try {
    const { email, password } = req.body
    
    const user = await User.findOne({ email, isBlocked: false })
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials or account blocked" })
    }
    
    const isValidPassword = await bcrypt.compare(password, user.password)
    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid credentials" })
    }
    
    // Update last login
    user.lastLogin = Date.now()
    await user.save()
    
    res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        preferences: user.preferences
      }
    })
  } catch (error) {
    console.error("Error logging in:", error)
    res.status(500).json({ message: "Error logging in" })
  }
})

// Get comments for a stream
app.get("/api/user/comments/:streamId", async (req, res) => {
  try {
    const { streamId } = req.params
    
    const comments = await Comment.find({ 
      streamId, 
      isModerated: true,
      isSpam: false 
    })
      .sort({ createdAt: -1 })
      .limit(100)
    
    res.status(200).json(comments)
  } catch (error) {
    console.error("Error fetching comments:", error)
    res.status(500).json({ message: "Error fetching comments" })
  }
})

// Add comment to a stream
app.post("/api/user/comment", async (req, res) => {
  try {
    const { streamId, userName, userEmail, content } = req.body
    
    if (!streamId || !userName || !userEmail || !content) {
      return res.status(400).json({ message: "All fields are required" })
    }
    
    // Verify stream exists
    const stream = await Stream.findById(streamId)
    if (!stream) {
      return res.status(404).json({ message: "Stream not found" })
    }
    
    const newComment = new Comment({
      streamId,
      userName,
      userEmail,
      content,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    })
    
    await newComment.save()
    
    // Log analytics
    await new Analytics({
      streamId,
      type: 'comment',
      data: { commentId: newComment._id, userName, userEmail }
    }).save()
    
    res.status(201).json({
      message: "Comment added successfully",
      comment: newComment
    })
  } catch (error) {
    console.error("Error adding comment:", error)
    res.status(500).json({ message: "Error adding comment" })
  }
})

// Update comment reaction
app.put("/api/user/comment/:commentId/reaction", async (req, res) => {
  try {
    const { commentId } = req.params
    const { reactionType } = req.body
    
    const validReactions = ['amen', 'praise', 'fire', 'heart', 'sad']
    if (!validReactions.includes(reactionType)) {
      return res.status(400).json({ message: "Invalid reaction type" })
    }
    
    const comment = await Comment.findById(commentId)
    if (!comment) {
      return res.status(404).json({ message: "Comment not found" })
    }
    
    comment.reactions[reactionType] = (comment.reactions[reactionType] || 0) + 1
    await comment.save()
    
    // Log analytics
    await new Analytics({
      type: 'reaction',
      data: { commentId, reactionType }
    }).save()
    
    res.status(200).json({
      message: "Reaction updated successfully",
      comment
    })
  } catch (error) {
    console.error("Error updating reaction:", error)
    res.status(500).json({ message: "Error updating reaction" })
  }
})

// Submit testimony
app.post("/api/user/testimony", async (req, res) => {
  try {
    const { name, email, title, testimony, category } = req.body
    
    if (!name || !email || !title || !testimony) {
      return res.status(400).json({ message: "All fields are required" })
    }
    
    const newTestimony = new Testimony({
      name,
      email,
      title,
      testimony,
      category: category || 'other'
    })
    
    await newTestimony.save()
    
    // Log analytics
    await new Analytics({
      type: 'testimony_submission',
      data: { testimonyId: newTestimony._id, category }
    }).save()
    
    res.status(201).json({
      message: "Testimony submitted successfully",
      testimony: newTestimony
    })
  } catch (error) {
    console.error("Error submitting testimony:", error)
    res.status(500).json({ message: "Error submitting testimony" })
  }
})

// Submit contact form
app.post("/api/user/contact", async (req, res) => {
  try {
    const { name, email, subject, message } = req.body
    
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ message: "All fields are required" })
    }
    
    const newContact = new Contact({
      name,
      email,
      subject,
      message,
      priority: subject.toLowerCase().includes('urgent') ? 'high' : 'medium'
    })
    
    await newContact.save()
    
    res.status(201).json({
      message: "Contact form submitted successfully",
      contact: newContact
    })
  } catch (error) {
    console.error("Error submitting contact form:", error)
    res.status(500).json({ message: "Error submitting contact form" })
  }
})

// Get public testimonies
app.get("/api/testimonies/public", async (req, res) => {
  try {
    const testimonies = await Testimony.find({ 
      isApproved: true, 
      isPublic: true 
    })
      .sort({ createdAt: -1 })
      .limit(20)
    
    res.status(200).json(testimonies)
  } catch (error) {
    console.error("Error fetching public testimonies:", error)
    res.status(500).json({ message: "Error fetching testimonies" })
  }
})

// Submit prayer request
app.post("/api/user/prayer-request", async (req, res) => {
  try {
    const { name, email, subject, prayerRequest, category, isConfidential } = req.body
    
    if (!name || !email || !subject || !prayerRequest) {
      return res.status(400).json({ message: "All fields are required" })
    }
    
    const newPrayerRequest = new PrayerRequest({
      name,
      email,
      subject,
      prayerRequest,
      category: category || 'other',
      isConfidential: isConfidential || false,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    })
    
    await newPrayerRequest.save()
    
    // Log analytics
    await new Analytics({
      type: 'prayer_request',
      data: { prayerRequestId: newPrayerRequest._id, category }
    }).save()
    
    res.status(201).json({
      message: "Prayer request submitted successfully",
      prayerRequest: newPrayerRequest
    })
  } catch (error) {
    console.error("Error submitting prayer request:", error)
    res.status(500).json({ message: "Error submitting prayer request" })
  }
})

// Get chat messages for a stream
app.get("/api/user/chat-messages/:streamId", async (req, res) => {
  try {
    const { streamId } = req.params
    const { messageType = 'chat' } = req.query
    
    const messages = await ChatMessage.find({ 
      streamId, 
      messageType,
      isModerated: true,
      isSpam: false 
    })
      .sort({ createdAt: -1 })
      .limit(100)
    
    res.status(200).json(messages)
  } catch (error) {
    console.error("Error fetching chat messages:", error)
    res.status(500).json({ message: "Error fetching chat messages" })
  }
})

// Add chat message
app.post("/api/user/chat-message", async (req, res) => {
  try {
    const { streamId, userName, userEmail, message, messageType = 'chat' } = req.body
    
    if (!streamId || !userName || !userEmail || !message) {
      return res.status(400).json({ message: "All fields are required" })
    }
    
    // Verify stream exists
    const stream = await Stream.findById(streamId)
    if (!stream) {
      return res.status(404).json({ message: "Stream not found" })
    }
    
    const newChatMessage = new ChatMessage({
      streamId,
      userName,
      userEmail,
      message,
      messageType,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    })
    
    await newChatMessage.save()
    
    // Log analytics
    await new Analytics({
      streamId,
      type: 'chat_message',
      data: { messageId: newChatMessage._id, messageType, userName }
    }).save()
    
    res.status(201).json({
      message: "Chat message added successfully",
      chatMessage: newChatMessage
    })
  } catch (error) {
    console.error("Error adding chat message:", error)
    res.status(500).json({ message: "Error adding chat message" })
  }
})

// Update chat message reaction
app.put("/api/user/chat-message/:messageId/reaction", async (req, res) => {
  try {
    const { messageId } = req.params
    const { reactionType } = req.body
    
    const validReactions = ['amen', 'praise', 'fire', 'heart', 'sad']
    if (!validReactions.includes(reactionType)) {
      return res.status(400).json({ message: "Invalid reaction type" })
    }
    
    const chatMessage = await ChatMessage.findById(messageId)
    if (!chatMessage) {
      return res.status(404).json({ message: "Chat message not found" })
    }
    
    chatMessage.reactions[reactionType] = (chatMessage.reactions[reactionType] || 0) + 1
    await chatMessage.save()
    
    // Log analytics
    await new Analytics({
      type: 'reaction',
      data: { messageId, reactionType, messageType: 'chat' }
    }).save()
    
    res.status(200).json({
      message: "Reaction updated successfully",
      chatMessage
    })
  } catch (error) {
    console.error("Error updating chat message reaction:", error)
    res.status(500).json({ message: "Error updating reaction" })
  }
})

// Add stream reaction endpoint
app.post("/api/user/stream-reaction", async (req, res) => {
  try {
    const { streamId, reactionType, userName, userEmail } = req.body;
    const validReactions = ["amen", "praise", "fire", "heart", "sad"];
    if (!streamId || !reactionType) {
      return res.status(400).json({ message: "streamId and reactionType are required" });
    }
    if (!validReactions.includes(reactionType)) {
      return res.status(400).json({ message: "Invalid reaction type" });
    }
    const stream = await Stream.findById(streamId);
    if (!stream) {
      return res.status(404).json({ message: "Stream not found" });
    }
    stream.reactions[reactionType] = (stream.reactions[reactionType] || 0) + 1;
    await stream.save();
    // Log analytics
    await new Analytics({
      streamId,
      type: "reaction",
      data: { reactionType, userName, userEmail }
    }).save();
    res.status(200).json({
      message: "Reaction added successfully",
      reactions: stream.reactions
    });
  } catch (error) {
    console.error("Error adding stream reaction:", error);
    res.status(500).json({ message: "Error adding stream reaction" });
  }
});

// Event Management Routes

// Admin: Get all events
app.get('/api/admin/events', authenticateToken, async (req, res) => {
  try {
    const events = await Event.find().sort({ startDate: 1 });
    res.status(200).json({ events });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching events' });
  }
});
// Admin: Create event (with imageUrl and videoUrl support)
app.post('/api/admin/event', authenticateToken, async (req, res) => {
  try {
    const { title, description, startDate, endDate, venue, imageUrl, videoUrl, videoDuration, category } = req.body;
    if (videoUrl && (!videoDuration || videoDuration > 600)) {
      return res.status(400).json({ message: 'Video duration must be 10 minutes (600 seconds) or less.' });
    }
    const event = new Event({
      title,
      description,
      startDate,
      endDate,
      venue,
      imageUrl,
      videoUrl,
      videoDuration,
      category,
      createdBy: req.admin._id
    });
    await event.save();
    res.status(201).json({ message: 'Event created', event });

    // Send notification to all admins (do not send another response)
    const admins = await Admin.find({});
    for (const admin of admins) {
      await sendNotification({
        recipient: admin._id,
        title: 'New Event Created',
        message: `Event '${title}' was created by ${req.admin.username}`,
        type: 'event',
        email: admin.email,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        location: req.headers['x-forwarded-for'] || req.connection.remoteAddress
      });
    }
  } catch (error) {
    // Only send a response if one hasn't been sent yet
    if (!res.headersSent) {
      res.status(500).json({ message: 'Error creating event' });
    } else {
      console.error('Error after response sent:', error);
    }
  }
});
// Admin: Update event
app.put('/api/admin/event/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body, updatedAt: Date.now() };
    if (updateData.videoUrl && (!updateData.videoDuration || updateData.videoDuration > 600)) {
      return res.status(400).json({ message: 'Video duration must be 10 minutes (600 seconds) or less.' });
    }
    const event = await Event.findByIdAndUpdate(id, updateData, { new: true });
    if (!event) return res.status(404).json({ message: 'Event not found' });
    res.status(200).json({ message: 'Event updated', event });
  } catch (error) {
    res.status(500).json({ message: 'Error updating event' });
  }
});
// Admin: Delete event
app.delete('/api/admin/event/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const event = await Event.findByIdAndDelete(id);
    if (!event) return res.status(404).json({ message: 'Event not found' });
    res.status(200).json({ message: 'Event deleted' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting event' });
  }
});
// Public: Get upcoming events
app.get('/api/events/upcoming', async (req, res) => {
  try {
    const now = new Date();
    const events = await Event.find({ startDate: { $gte: now } }).sort({ startDate: 1 });
    res.status(200).json({ events });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching events' });
  }
});

// General Chat Management Routes

// User/Guest: Start or send message in a general chat
app.post('/api/user/general-chat', async (req, res) => {
  try {
    const { name, email, userId, message } = req.body;
    if (!name || !email || !message) return res.status(400).json({ message: 'Name, email, and message are required' });
    // Find or create chat for this user/email
    let chat = await GeneralChat.findOne({ 'participants.email': email });
    if (!chat) {
      chat = new GeneralChat({
        participants: [{ userId, name, email, isAdmin: false }],
        messages: []
      });
    }
    chat.participants = [{ userId, name, email, isAdmin: false }];
    chat.messages.push({ sender: { userId, name, email, isAdmin: false }, message });
    chat.updatedAt = Date.now();
    await chat.save();
    res.status(201).json({ message: 'Message sent', chatId: chat._id });
  } catch (error) {
    res.status(500).json({ message: 'Error sending message' });
  }
});

// User/Guest: Fetch messages in a general chat
app.get('/api/user/general-chat/:chatId/messages', async (req, res) => {
  try {
    const { chatId } = req.params;
    const chat = await GeneralChat.findById(chatId);
    if (!chat) return res.status(404).json({ message: 'Chat not found' });
    res.status(200).json({ messages: chat.messages });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching chat messages' });
  }
});

// Admin: Fetch all general chats (chat list)
app.get('/api/admin/general-chats', authenticateToken, async (req, res) => {
  try {
    const chats = await GeneralChat.find({}, 'participants updatedAt').sort({ updatedAt: -1 });
    res.status(200).json({ chats });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching chats' });
  }
});

// Admin: Fetch messages in a chat
app.get('/api/admin/general-chat/:chatId', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const chat = await GeneralChat.findById(chatId);
    if (!chat) return res.status(404).json({ message: 'Chat not found' });
    res.status(200).json({ messages: chat.messages, participants: chat.participants });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching chat messages' });
  }
});

// Admin: Reply in a chat
app.post('/api/admin/general-chat/:chatId/reply', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { message } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });
    const chat = await GeneralChat.findById(chatId);
    if (!chat) return res.status(404).json({ message: 'Chat not found' });
    const admin = req.admin;
    chat.messages.push({ sender: { name: admin.username, email: admin.email, isAdmin: true }, message });
    chat.updatedAt = Date.now();
    await chat.save();
    res.status(201).json({ message: 'Reply sent' });
  } catch (error) {
    res.status(500).json({ message: 'Error sending reply' });
  }
});

// Health check endpoint
// Root endpoint for basic health check
app.get("/", (req, res) => {
  res.status(200).json({
    message: "Livestream API Server",
    status: "running",
    timestamp: new Date().toISOString(),
    version: "1.0.0"
  });
});

// Simple test endpoint
app.get("/test", (req, res) => {
  res.status(200).json({
    message: "Server is working!",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.status(200).json({ 
    message: "Livestream server is running",
    timestamp: new Date().toISOString(),
    version: "2.0.0"
  })
})

const PORT = process.env.PORT 
// Keep-Alive Function to Prevent Render Downtime
const keepAlive = async () => {
  try {
    // Only run keep-alive if we have an external URL (production)
    if (!process.env.RENDER_EXTERNAL_URL) {
      console.log("🔄 Keep-alive skipped - no external URL configured (development mode)");
      return;
    }

    const baseUrl = process.env.RENDER_EXTERNAL_URL;
    const endpoints = ['/api/health', '/', '/test']; // Try health endpoint first, then root, then test
    
    for (const endpoint of endpoints) {
      try {
        const healthUrl = `${baseUrl}${endpoint}`;
        console.log(`🔄 Starting keep-alive ping to: ${healthUrl}`);
        
        // Parse URL to get hostname and port
        const url = new URL(healthUrl);
        const options = {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname,
          method: 'GET',
          timeout: 10000, // 10 seconds timeout
          headers: {
            'User-Agent': 'Livestream-Server-KeepAlive/1.0',
            'Accept': 'application/json',
            'Connection': 'keep-alive'
          }
        };

        // Use HTTPS for HTTPS URLs, HTTP for HTTP URLs
        const requestModule = url.protocol === 'https:' ? https : http;
        const request = requestModule.request(options, (response) => {
          let data = '';
          response.on('data', (chunk) => {
            data += chunk;
          });
          
          response.on('end', () => {
            if (response.statusCode === 200) {
              try {
                const jsonData = JSON.parse(data);
                console.log(`✅ Keep-alive ping successful at ${new Date().toISOString()}`);
                if (endpoint === '/api/health') {
                  console.log(`📊 Server status: ${jsonData.message} | DB: ${jsonData.database} | Uptime: ${Math.round(jsonData.uptime)}s`);
                } else {
                  console.log(`📊 Server status: ${jsonData.message} | Status: ${jsonData.status}`);
                }
                return; // Success, exit the loop
              } catch (e) {
                console.log(`✅ Keep-alive ping successful at ${new Date().toISOString()}`);
                console.log(`📊 Server response: ${data.substring(0, 100)}...`);
                return; // Success, exit the loop
              }
            } else {
              console.error(`❌ Keep-alive ping failed for ${endpoint}: ${response.statusCode}`);
              if (endpoint === '/api/health') {
                console.error(`📄 Response headers:`, response.headers);
                console.error(`📄 Response data: ${data.substring(0, 200)}...`);
              }
            }
          });
        });

        request.on('error', (error) => {
          console.error(`❌ Keep-alive ping error for ${endpoint}: ${error.message}`);
          if (error.code === 'ECONNRESET' || error.code === 'ENOTFOUND') {
            console.error(`🔍 Network error details: ${error.code} - ${error.syscall}`);
          }
        });

        request.on('timeout', () => {
          console.error(`⏰ Keep-alive ping timeout for ${endpoint}`);
          request.destroy();
        });

        request.end();
        
        // Wait a bit before trying the next endpoint
        await new Promise(resolve => setTimeout(resolve, 2000));
        
      } catch (error) {
        console.error(`❌ Keep-alive ping error for ${endpoint}: ${error.message}`);
      }
    }
  } catch (error) {
    console.error(`❌ Keep-alive ping error: ${error.message}`);
  }
};

// Internal keep-alive function (doesn't make external requests)
const internalKeepAlive = () => {
  const now = new Date();
  console.log(`🔄 Internal keep-alive: Server running since ${Math.round(process.uptime())}s at ${now.toISOString()}`);
  
  // Log server stats
  const memUsage = process.memoryUsage();
  console.log(`📊 Memory usage: ${Math.round(memUsage.heapUsed / 1024 / 1024)}MB / ${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`);
  
  // Check database connection
  const dbStatus = mongoose.connection.readyState === 1 ? "Connected" : "Disconnected";
  console.log(`📊 Database: ${dbStatus}`);
  
  // Log active connections
  const socketCount = socketIo?.engine?.clientsCount || 0;
  console.log(`📊 Active connections: ${socketCount}`);
};

// Simple keep-alive function
const simpleKeepAlive = () => {
  console.log(`🔄 Simple keep-alive: Server is running at ${new Date().toISOString()}`);
};

// Start keep-alive intervals
const startKeepAlive = () => {
  // External keep-alive (only in production)
  if (process.env.RENDER_EXTERNAL_URL) {
    console.log("🚀 Starting external keep-alive (production mode)");
    setInterval(keepAlive, 14 * 60 * 1000); // Every 14 minutes
  }
  
  // Internal keep-alive (always running)
  console.log("🚀 Starting internal keep-alive");
  setInterval(internalKeepAlive, 5 * 60 * 1000); // Every 5 minutes
  
  // Simple keep-alive (always running)
  console.log("🚀 Starting simple keep-alive");
  setInterval(simpleKeepAlive, 2 * 60 * 1000); // Every 2 minutes
};

// Start the server
app.listen(PORT || 5000, () => {
  console.log(`🚀 Livestream server running on port ${PORT || 5000}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT || 5000}/api/health`);
  
  // Start keep-alive functions
  startKeepAlive();
});

// Simple keep-alive endpoint for self-ping
app.get('/keep-alive', (req, res) => {
  res.status(200).json({ message: 'Keep-alive ping', timestamp: new Date().toISOString() });
});

// Add a self-ping keep-alive every 15 minutes
setInterval(() => {
  const http = require('http');
  const port = PORT || 5000;
  const url = `http://localhost:${port}/keep-alive`;
  http.get(url, (res) => {
    console.log(`🔄 Self keep-alive ping: ${url} - Status: ${res.statusCode}`);
  }).on('error', (err) => {
    console.error('Self keep-alive error:', err.message);
  });
}, 15 * 60 * 1000); // Every 15 minutes