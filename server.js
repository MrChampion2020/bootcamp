const express = require("express")
const mongoose = require("mongoose")
const nodemailer = require("nodemailer")
const cors = require("cors")
const dotenv = require('dotenv')
dotenv.config() // Load environment variables from .env file
const app = express()

app.use(cors())
app.use(express.json())

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err))

// User Schema
const userSchema = new mongoose.Schema({
  fullName: String,
  email: String,
  phone: String,
  address: String,
  dob: String,
  education: String,
  skill: String,
  experience: String,
  location: String,
  expectations: String,
  attendance: { type: Number, default: 0 },
  progress: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
})

const User = mongoose.model("User", userSchema)

// Nodemailer Setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.user, // Use environment variable
    pass: process.env.pass, // Use environment variable
  },
})

// Register Endpoint
app.post("/api/register", async (req, res) => {
  try {
    const userData = req.body
    const newUser = new User(userData)
    await newUser.save()

    // Send email to user
    await transporter.sendMail({
      from: `"Christ Embassy Ibadan Zone 1" <${process.env.user}>`,
      to: userData.email,
      subject: "Bootcamp Registration Confirmation",
      html: `
        <h2>Thank You for Registering!</h2>
        <p>Dear ${userData.fullName},</p>
        <p>We are excited to confirm your registration for the Christ Embassy 2025 Tech Bootcamp.</p>
        <p><strong>Details:</strong></p>
        <ul>
          <li>Date: May 25th - June 1st, 2025</li>
          <li>Location: Church Auditorium, Ibadan</li>
          <li>Time: 8AM prompt, Sunday 31st May</li>
        </ul>
        <p>We look forward to seeing you there!</p>
        <p>Best regards,<br>Christ Embassy Ibadan Zone 1 Team</p>
      `,
    })

    // Send email to admin
    await transporter.sendMail({
      from: `"Christ Embassy Ibadan Zone 1" <${process.env.user}>`,
      to: process.env.to, // Replace with admin email
      subject: "New Bootcamp Registration",
      html: `
        <h2>New Registration</h2>
        <p><strong>Full Name:</strong> ${userData.fullName}</p>
        <p><strong>Email:</strong> ${userData.email}</p>
        <p><strong>Phone:</strong> ${userData.phone}</p>
        <p><strong>Address:</strong> ${userData.address}</p>
        <p><strong>Date of Birth:</strong> ${userData.dob}</p>
        <p><strong>Education:</strong> ${userData.education}</p>
        <p><strong>Skill:</strong> ${userData.skill}</p>
        <p><strong>Experience:</strong> ${userData.experience}</p>
        <p><strong>Location:</strong> ${userData.location}</p>
        <p><strong>Expectations:</strong> ${userData.expectations}</p>
      `,
    })

    res.status(200).json({ message: "Registration successful" })
  } catch (error) {
    console.error("Error in registration:", error)
    res.status(500).json({ message: "Error in registration" })
  }
})

// Get All Users (for Admin)
app.get("/api/users", async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 })
    res.status(200).json(users)
  } catch (error) {
    console.error("Error fetching users:", error)
    res.status(500).json({ message: "Error fetching users" })
  }
})

// Update User Attendance and Progress (for Admin)
app.put("/api/users/:id", async (req, res) => {
  try {
    const { id } = req.params
    const { attendance, progress } = req.body
    const updatedUser = await User.findByIdAndUpdate(
      id,
      { attendance, progress },
      { new: true }
    )
    res.status(200).json(updatedUser)
  } catch (error) {
    console.error("Error updating user:", error)
    res.status(500).json({ message: "Error updating user" })
  }
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))