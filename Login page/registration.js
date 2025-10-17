import express from "express"
import * as bcrypt from "bcrypt"
import { user, admin, ReviewDatabase, Database } from "../DB/model.js"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"
import { v2 as cloudinary } from "cloudinary"
import cloudinaryConfig from "../Config/Cloudinary.js"
import brevo from'@getbrevo/brevo'
import crypto from "crypto"
import { sendEmail, sendAdminResetEmail, sendLoginVerificationEmail, passwordSuccessEmail, verificationSuccess } from "./Dashboard.js"

dotenv.config()

cloudinaryConfig();

const registration = express.Router()

const apiInstance = new brevo.TransactionalEmailsApi();
const apiKey = apiInstance.authentications['apiKey'];
apiKey.apiKey = process.env.BREVO_API_KEY;

registration.post('/register', async(req,res) => {
    const {name, email, password, confirmpassword} = req.body;
    
    if(password !== confirmpassword) {
        return res.status(400).json({message:'Password does not match'})
    }

    try {
        const existinguser = await user.findOne({email})
        if(existinguser) {
            return res.status(400).json({
                message:'Username already Exists'
            })
        }

        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const loginVerificationExpires = Date.now() + 3600000; // 1 hour
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        const newuser = new user({
            name,
            email,
            password: hashedPassword,
            isEmailVerified: false,
            loginVerificationCode: verificationCode,
            loginVerificationExpires: loginVerificationExpires
        });

        await newuser.save();

        const verificationLink =  `${process.env.VERIFICATION_LINK}/${loginVerificationExpires}`

        // Send first-time login verification
        const verificationResult = await sendLoginVerificationEmail(
            email,
            'User Account Verification',
            name,
            verificationCode,
            verificationLink,
        );

        if (!verificationResult.success) {
            throw new Error('Failed to send verification email');
        }

        res.status(201).json({
            success: true,
            message: 'User registered successfully. Please check your email to verify your account.',
            requiresVerification: true,
            email: email
        });

    } catch(err) {
        console.error('User registration error:', err);
        res.status(500).json({message: 'Server Error'})
    }
});

registration.post('/login', async(req,res) => {
    const {email, password} = req.body;
         
    try {
        const existinguser = await user.findOne({email})
        if(!existinguser) {
            return res.status(400).json({
                success: false,
                message: 'User not found'
            });
        }

        const ispasswordcorrect = await bcrypt.compare(password, existinguser.password)
        if(!ispasswordcorrect) {
            return res.status(400).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check email verification status
        if (!existinguser.isEmailVerified) {
            return res.status(400).json({
                success: false,
                message: 'Please verify your email to complete login',
                requiresVerification: true,
                email: email
            });
        }

        // If email is verified, generate token and complete login
        const token = jwt.sign(
            {
                id: existinguser._id,
                name: existinguser.name,
                email: existinguser.email,
                isAdmin: false
            },
            process.env.SECRET_TOKEN,
            { expiresIn: "1d" }
        );

        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            userId: existinguser._id
        });
            
    } catch(err) {
        console.error('User login error:', err);
        res.status(500).json({
            success: false,
            message: 'Server error occurred'
        });
    }
})

registration.post('/AdminRegister', async(req,res) => {
    const {name, email, password, confirmpassword} = req.body;

    if(password !== confirmpassword) {
        return res.status(400).json({message:'Password does not match'})
    }

    try {
        const existinguser = await admin.findOne({email})
        if(existinguser) {
            return res.status(400).json({
                message:'Username already Exists'
            })
        }
        
        const hashedPassword = bcrypt.hashSync(password, 10);
        
        // Generate verification token
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const loginVerificationExpires = Date.now() + 3600000; // 1 hour

        const newuser1 = new admin({
            name,
            email,
            password: hashedPassword,
            isEmailVerified: false,
            loginVerificationCode: verificationCode,
            loginVerificationExpires: loginVerificationExpires
        });

        await newuser1.save();

        // Create verification link
        const verificationLink =  `${process.env.VERIFICATION_LINK_ADMIN}/${loginVerificationExpires}`;
        
        // Send verification email
        const verificationResult = await sendLoginVerificationEmail(
            email,
            'Admin Account Verification',
            name,
            verificationCode,
            verificationLink,
        );

        if (!verificationResult.success) {
            throw new Error('Failed to send verification email');
        }

        res.status(201).json({
            success: true,
            message: 'Admin registered successfully. Please check your email to verify your account.',
            requiresVerification: true,
            email: email
        });

    } catch(err) {
        console.error('Admin registration error:', err);
        res.status(500).json({message: 'Server Error'})
    }
});

registration.post('/verify-login', async (req, res) => {
    const { email, verificationCode, isAdmin } = req.body;
    
    if (!email || !verificationCode) {
        return res.status(400).json({
            success: false,
            message: 'Email and verification code are required'
        });
    }

    try {
        const UserModel = isAdmin ? admin : user;
        const existingUser = await UserModel.findOne({ email });

        if (!existingUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if code needs to be regenerated
        if (!existingUser.loginVerificationExpires || 
            existingUser.loginVerificationExpires < Date.now()) {
            // Generate new verification code
            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            existingUser.loginVerificationCode = verificationCode;
            existingUser.loginVerificationExpires = Date.now() + 600000; // 10 minutes
            await existingUser.save();

            // Send new verification code
            await sendLoginVerificationEmail(
                email,
                isAdmin ? 'Admin Verification' : 'User Verification',
                existingUser.name,
                verificationCode
            );

            return res.status(400).json({
                success: false,
                message: 'Verification code expired. New code has been sent to your email.',
                requiresNewCode: true
            });
        }

        // Check if verification code matches and hasn't expired
        if (existingUser.loginVerificationCode !== verificationCode ||
            !existingUser.loginVerificationExpires ||
            existingUser.loginVerificationExpires < Date.now()) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired verification code'
            });
        }

        // Update verification status and clear verification fields
        existingUser.isEmailVerified = true;
        existingUser.loginVerificationCode = undefined;
        existingUser.loginVerificationExpires = undefined;
        await existingUser.save();

        // Send verification success email
        if(isAdmin){
            await verificationSuccess(
                existingUser.email,
                "Admin Verification Successful",
                existingUser.name,
            )
        } else {
            await verificationSuccess(
                existingUser.email,
                "User Verification Successful",
                existingUser.name,
                isAdmin
            )
        }


        const token = jwt.sign(
            { 
                id: existingUser._id,
                name: existingUser.name,
                email: existingUser.email,
                isAdmin 
            },
            process.env.SECRET_TOKEN,
            { expiresIn: "1d" }
        );
        return res.status(200).json({
            success: true,
            message: `${isAdmin ? 'Admin' : 'User'} email has been verified successfully`,
            token,
            userId: existingUser._id
        });

    } catch (error) {
        console.error('Verification error:', error);
        return res.status(500).json({
            success: false,
            message: 'An error occurred during verification'
        });
    }
});

registration.post('/AdminLogin', async(req, res) => {
    const { email, password } = req.body;
    try {
        const existinguser = await admin.findOne({ email });
        if (!existinguser) {
            return res.status(400).json({
                success: false,
                message: "Admin not found"
            });
        }

        const ispasswordcorrect = await bcrypt.compare(password, existinguser.password);
        if (!ispasswordcorrect) {
            return res.status(400).json({
                success: false,
                message: 'Invalid credentials'
            });
        }

        // Check email verification status
        if (!existinguser.isEmailVerified) {
            return res.status(400).json({
                success: false,
                message: 'Please verify your email to complete login',
                requiresVerification: true,
                email: email
            });
        }

        // If email is verified, proceed with login
        const token = jwt.sign(
            {
                id: existinguser._id,
                name: existinguser.name,
                email: existinguser.email,
                isAdmin: true,
            },
            process.env.SECRET_TOKEN,
            { expiresIn: "1d" }
        );

        if (!existinguser.isEmailVerified) {
            existinguser.isEmailVerified = true;
            await existinguser.save();
        }


        res.status(200).json({
            success: true,
            message: 'Login successful',
            token,
            userId: existinguser._id
        });

    } catch(err) {
        console.error('Admin login error:', err);
        res.status(500).json({
            success: false,
            message: 'Server error occurred'
        });
    }
});

registration.post('/products/:id/reviews', async (req, res) => {
    const id = req.params.id;
    const {name, rating, comment} = req.body;
    if (!name || name.trim() === "") {
        return res.status(400).json({ message: "Reviewer name is required" });
    }
    console.log("Review POST body:", req.body)
    try {
        const existingReview = await ReviewDatabase.findOne({ productId: id, name });
        if (existingReview) {
            return res.status(400).json({ message: "You have already reviewed this product" });
        }
        const newReview = new ReviewDatabase({
            productId: id,
            name,
            rating,
            comment
        });
        await newReview.save();
        res.status(201).json({ success:true, message: "Review added successfully" });
    } catch (err) {
        console.error('Error adding review:', err);
        res.status(500).json({ message: "Internal server error" });
    }
}
);

registration.get('/products/:id/reviews', async (req, res) => {
    const id = req.params.id;
    try {
        const reviews = await ReviewDatabase.find({ productId: id });
        res.status(200).json({ success: true, reviews });;
    } catch (err) {
        console.error('Error fetching reviews:', err);
        res.status(500).json({ message: "Internal server error" });
    }
});

registration.delete('/products/:id/reviews', async (req, res) => {
    const id = req.params.id;
    const { name } = req.body;
    try {
        const review = await ReviewDatabase.findOneAndDelete({ productId: id, name });
        if (!review) {
            return res.status(404).json({ success: false, message: "Review not found" });
        }
        res.status(200).json({ success: true, message: "Review deleted successfully" });;
    } catch (err) {
        console.error('Error deleting review:', err);
        res.status(500).json({ message: "Internal server error" });
    }
});

registration.post('/forgot-password', async (req, res) => {
  const { email, isAdmin } = req.body;
  
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required' });
  }
  
  try {
    // Find user by email using appropriate model
    const UserModel = isAdmin ? admin : user;
    const existingUser = await UserModel.findOne({ email });
    
    if (existingUser) {
      // Generate reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
      
      // Save token and expiry to user document
      existingUser.resetPasswordToken = resetToken;
      existingUser.resetPasswordExpires = resetTokenExpiry;
      await existingUser.save();

      // Use the correct reset link based on user type
      const resetLink = isAdmin ? 
        `${process.env.RESET_LINK_ADMIN}/${resetToken}` :
        `${process.env.RESET_LINK}/${resetToken}`;

      console.log(`${isAdmin ? 'Admin' : 'User'} Reset Link:`, resetLink);

      // Send appropriate email based on user type
      const emailResult = isAdmin ? 
        await sendAdminResetEmail(
          existingUser.email,
          'Admin Password Reset - Art Vista Gallery',
          existingUser.name,
          resetLink  // Changed from adminResetLink to resetLink
        ) :
        await sendEmail(
          existingUser.email,
          'Reset Your Password - Art Vista Gallery',
          existingUser.name,
          resetLink
        );
      
      if (!emailResult.success) {
        // If email fails, remove token from user document
        existingUser.resetPasswordToken = undefined;
        existingUser.resetPasswordExpires = undefined;
        await existingUser.save();
        
        return res.status(500).json({ 
          success: false, 
          message: 'Failed to send password reset email' 
        });
      }
    }

    return res.status(200).json({
      success: true,
      message: 'If your email is registered with us, you will receive password reset instructions shortly'
    });
    
  } catch (error) {
    console.error('Password reset request error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'An error occurred. Please try again later.' 
    });
  }
});

registration.post('/reset-password', async (req, res) => {
  const { token, newPassword, isAdmin } = req.body;
  
  if (!token || !newPassword) {
    return res.status(400).json({ 
      success: false, 
      message: 'Token and new password are required' 
    });
  }
  
  try {
    const UserModel = isAdmin ? admin : user;
    
    // Find user with valid token that hasn't expired
    const existingUser = await UserModel.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
    });
    
    if (!existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Password reset token is invalid or has expired'
      });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update user's password and clear reset token
    existingUser.password = hashedPassword;
    existingUser.resetPasswordToken = undefined;
    existingUser.resetPasswordExpires = undefined;
    
    await existingUser.save();
    
    // Send appropriate confirmation email based on user type
    if (isAdmin) {
      await passwordSuccessEmail(
        existingUser.email,
        'Admin Password Changed Successfully',
        existingUser.name
      );
    } else {
      await passwordSuccessEmail(
        existingUser.email,
        'User Password Changed Successfully',
        existingUser.name
      );
    }
    
    return res.status(200).json({
      success: true,
      message: `${isAdmin ? 'Admin' : 'User'} password has been reset successfully`
    });
    
  } catch (error) {
    console.error('Password reset error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'An error occurred. Please try again later.' 
    });
  }
});



export default registration

