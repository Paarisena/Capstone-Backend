import {admin, Database, profile, Verification } from '../DB/model.js'
import dotenv from 'dotenv'
import {v2 as cloudinary} from 'cloudinary'
import cloudinaryConfig from '../Config/Cloudinary.js'
import brevo from'@getbrevo/brevo'

cloudinaryConfig();

dotenv.config()

const apiInstance = new brevo.TransactionalEmailsApi();
const apiKey = apiInstance.authentications['apiKey'];
apiKey.apiKey = process.env.BREVO_API_KEY;

const addProduct = async(req, res) =>{
    try{
        const {productName, productDescription, Category, Price } = req.body
        const adminId = req.user && req.user.id;
        console.log("Admin ID:", adminId);
        if (!productName || !productDescription || !Category || !Price || !adminId) {
            return res.status(400).json({ message: "Missing required fields" });
        }
        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(400).json({ message: "No files were uploaded" });
        }
        console.log('Request Body:', req.body);
        console.log('Request Files:', req.files);

        const image1 = req.files.image1 && req.files.image1[0]
        const image2 = req.files.image2 && req.files.image2[0]
        const image3 = req.files.image3 && req.files.image3[0]
        const image4 = req.files.image4 && req.files.image4[0]

        const images = [image1, image2, image3, image4].filter((item) => item !== undefined)

        
        const imageUrls = await Promise.all(images.map(async (item) =>{
            const result = await cloudinary.uploader.upload(item.path,{resource_type:"image"})
            return result.secure_url
        }))
        console.log(productName, productDescription, Category, Price)
        console.log(imageUrls)

    const productData = new Database({
        productName,
        productDescription,
        Category,
        Price,
        Image: imageUrls,
        createdBy:adminId,
        isPublic: true
    })

    console.log(productData)

    
    await productData.save()
    res.status(201).json({ message: "Product added successfully" });
} catch (err) {
    console.error('Error in Add Product',err); 
    res.status(500).json({ message: "Internal server error" });
}

}


const listProducts = async(req, res) =>{
    try{
        const adminId = req.user && req.user.id;
        console.log("Admin ID:", adminId);
        const products = await Database.find({createdBy:adminId})
        res.json({success:true,products})
    }catch(err){
        console.log(err)
        res.status(500).json({ message: "Internal server error " });
    }
}

const listPublicProducts = async(req,res) =>{
    try{
        const products = await Database.find({isPublic:true})
        res.json({success:true,products})
    }catch(err){
        console.log(err)
        res.status(500).json({ message: "Internal server error " });
    }
}

const editProduct = async(req,res) =>{
    try{
        const {id} = req.params
        const updatedData = req.body
        const adminId = req.user && req.user.id;
        const product  = await Database.findOneAndUpdate(
            {_id:id, createdBy:adminId},
            {$set: updatedData},
            {new: true}
        );
        if (!product) {
            return res.status(404).json({ success: false, message: "Product not found or you do not have permission to edit it" });
        }
        res.json({ success: true, product });
    } catch (err) { 
        console.error('Error in Edit Product:', err);
        res.status(500).json({ message: "Internal server error" });
    }
};


const deleteProduct = async(req, res) =>{
    try {
        const  id  = req.params.id;
        // Find the product first
        const product = await Database.findById(id);
        if (!product) {
            return res.status(404).json({ success: false, message: "Product not found" });
        }

        // Delete images from Cloudinary
        if (product.Image && product.Image.length > 0) {
            for (const imageUrl of product.Image) {
                const publicId = extractCloudinaryPublicId(imageUrl);
                console.log("Original URL:", imageUrl);
                console.log("Extracted Cloudinary publicId:", publicId);
                if (publicId) {
                    await cloudinary.uploader.destroy(publicId);
                }
            }
        }

        // Now delete the product from the database
        const deleteproducts = await Database.findByIdAndDelete(id);
        res.json({ success: true, deleteproducts });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Internal server error " });
    }
};

// Helper to extract public_id from Cloudinary URL
function extractCloudinaryPublicId(url) {
    url = url.split('?')[0];
    const parts = url.split('/upload/');
    if (parts.length < 2) return null;
    let publicIdWithExt = parts[1].replace(/^v\d+\//, '');
    return publicIdWithExt.replace(/\.[^/.]+$/, "");
}


const singleProduct = async(req, res) =>{
    try{
        const {id} = req.params
        const singleProduct = await Database.findById(id)
         if (!singleProduct) {
            return res.status(404).json({ success: false, message: "Product not found" });
         }
         res.json({success:true,singleProduct})
    }catch(err){
        console.log(err)
        res.status(500).json({ message: "Internal server error " });
    }
}   

const reviewProduct = async(req,res) =>{
    try{
        const {id} = req.params
        const {review} = req.body
        if (!review) {
            return res.status(400).json({ message: "Review is required" });
        }
        const product = await Database.findById(id)
        if (!product) {
            return res.status(404).json({ message: "Product not found" });
        }
        product.reviews.push(review)
        await product.save()
        res.json({success:true, message: "Review added successfully", product})
    } catch(err){
        console.log(err)
        res.status(500).json({ message: "Internal server error " });
}
}

const addProfile = async (req, res) => {
    try {
        const {id} = req.params;
        const userId = req.user && req.user.id;
        console.log("userId from req.user:", userId);
        const { name, DOB, email, phone, address } = req.body;

        // Validate required fields before DB call
        if (!name || !DOB || !email || !phone || !address) {
            return res.status(400).json({ message: "Missing required fields" });
        }

        // Update if exists, else create (one profile per user)
        const prof = await profile.findOneAndUpdate(
            { userId },
            { $set: { name, DOB, email, phone, address } },
            { new: true, upsert: true }
        );

        res.status(200).json({ success: true, profile: prof });
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Internal server error" });
    }
};

const fetchProfile = async (req,res) =>{
    const response = await profile.findOne({ userId: req.user.id });
    console.log("Fetched profile:", response);
    if (!response) {
        return res.status(404).json({ success: false, message: "Profile not found" });
    }
    res.status(200).json({ success: true, profile: response });
}

const sendEmail = async (to, subject, recipientName = '', resetLink = '') => {
  try {
    const sendSmtpEmail = new brevo.SendSmtpEmail();
    
    sendSmtpEmail.sender = {
      name: process.env.SENDER_NAME || 'Art Vista Gallery',
      email: process.env.SENDER_EMAIL || 'noreply@avgallery.shop'
    };
    
    sendSmtpEmail.to = [{
      email: to,
      name: recipientName || to.split('@')[0]
    }];
    
    sendSmtpEmail.subject = subject;
    
    sendSmtpEmail.htmlContent = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #333; text-align: center;">Art Vista Gallery</h2>
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
          <h3 style="color: #444;">Hello ${recipientName},</h3>
          <p style="color: #666;">You requested to reset your password.</p>
          <p style="color: #666;">Please click the button below to reset your password:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}"
               style="background-color: #007bff; 
                      color: white; 
                      padding: 12px 25px; 
                      text-decoration: none; 
                      border-radius: 5px; 
                      display: inline-block;">
              Reset Password
            </a>
          </div>
          <p style="color: #666; margin-top: 20px;">This link will expire in 1 hour.</p>
          <p style="color: #999; font-size: 14px;">If you did not request this, please ignore this email.</p>
        </div>
      </div>
    `;

    const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
    console.log('Email sent successfully:', response);
    return { success: true, messageId: response.messageId };
  } catch (error) {
    console.error('Error sending email:', error);
    return { success: false, error: error.message };
  }
};

const sendAdminResetEmail = async (to, subject, recipientName = '', resetLink = '') => {
    try {
        const smtpEmail = new brevo.SendSmtpEmail();
        smtpEmail.sender = {
            name: process.env.SENDER_NAME || 'Art Vista Gallery',
            email: process.env.SENDER_EMAIL || 'noreply@avgallery.shop'
        };
        smtpEmail.to = [{
            email: to,
            name: recipientName || to.split('@')[0]
        }];
        smtpEmail.subject = 'Admin Portal - ' + subject;
        smtpEmail.htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333; text-align: center;">Art Vista Gallery - Admin Portal</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border: 1px solid #28a745;">
                    <h3 style="color: #444;">Hello ${recipientName},</h3>
                    <div style="background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px;">
                        <p style="color: #2e7d32; margin: 0;">
                            <strong>Important:</strong> This is an admin portal password reset request.
                        </p>
                    </div>
                    <p style="color: #666;">You requested to reset your admin portal password.</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetLink}"
                           style="background-color: #28a745; 
                                  color: white; 
                                  padding: 12px 25px; 
                                  text-decoration: none; 
                                  border-radius: 5px; 
                                  display: inline-block;
                                  font-weight: bold;">
                            Reset Admin Password
                        </a>
                    </div>
                    <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 20px;">
                        <p style="color: #856404; margin: 0;">
                            <strong>Security Notice:</strong> This admin reset link will expire in 1 hour.
                        </p>
                    </div>
                    <p style="color: #999; font-size: 14px; margin-top: 20px;">
                        If you did not request this admin password reset, please contact support immediately.
                    </p>
                </div>
            </div>
        `;

        const response = await apiInstance.sendTransacEmail(smtpEmail);
        console.log('Admin reset email sent successfully:', response);
        return { success: true, messageId: response.messageId };
    } catch (error) {
        console.error('Error sending admin reset email:', error);
        return { success: false, error: error.message };
    }
};

const passwordSuccessEmail = async (to, subject, recipientName = '') => {
    try {
        const sendSmtpEmail = new brevo.SendSmtpEmail();
        sendSmtpEmail.sender = {
            name: process.env.SENDER_NAME || 'Art Vista Gallery',
            email: process.env.SENDER_EMAIL || 'noreply@avgallery.shop'
        };
        sendSmtpEmail.to = [{
            email: to,
            name: recipientName || to.split('@')[0]
        }];
        sendSmtpEmail.subject = subject;
        sendSmtpEmail.htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
`;
        sendSmtpEmail.htmlContent += `
                <h2 style="color: #333; text-align: center;">Art Vista Gallery</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border: 1px solid #28a745;">
                    <h3 style="color: #444;">Hello ${recipientName},</h3>
                    <div style="background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px;">        
                        <p style="color: #2e7d32; margin: 0;">
                            <strong>Success!</strong> Your password has been changed successfully.
                        </p>
                    </div>
                    <p style="color: #666;">If you did not initiate this change, please contact support immediately.</p>
                    <p style="color: #999; font-size: 14px; margin-top: 20px;">Thank you for being a valued member of Art Vista Gallery.</p>
                </div>
            </div>
        `;  
        const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
        console.log('Password success email sent successfully:', response);
        return { success: true, messageId: response.messageId };
    } catch (error) {
        console.error('Error sending password success email:', error);
        return { success: false, error: error.message };
    }
};

const sendLoginVerificationEmail = async (to, subject, recipientName = '', verificationCode = '', verificationLink = '') => {
    try {
        const sendSmtpEmail = new brevo.SendSmtpEmail();
        sendSmtpEmail.sender = {
            name: process.env.SENDER_NAME || 'Art Vista Gallery',
            email: process.env.SENDER_EMAIL || 'noreply@avgallery.shop'
        };
        sendSmtpEmail.to = [{
            email: to,
            name: recipientName || to.split('@')[0]
        }];
        sendSmtpEmail.subject = subject;
        sendSmtpEmail.htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333; text-align: center;">Art Vista Gallery</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border: 1px solid #007bff;">
                    <h3 style="color: #444;">Hello ${recipientName},</h3>
                    <p style="color: #666;">Thank you for registering with Art Vista Gallery.</p>
                    
                    <div style="background-color: #e3f2fd; padding: 20px; border-radius: 5px; margin: 20px 0; text-align: center;">
                        <h2 style="color: #11b952ff; margin: 0;">Your Verification Code</h2>
                        <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 15px 0; color: #1976d2; background: white; padding: 15px; border-radius: 4px;">
                            ${verificationCode}
                        </div>
                    </div>
                    
                    <p style="color: #666;">You can verify your account in two ways:</p>
                    
                    <div style="margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-radius: 5px;">
                        <p style="color: #666; margin: 0 0 10px 0;">
                            <strong>Option 1:</strong> Enter the verification code above
                        </p>
                        <p style="color: #666; margin: 0;">
                            <strong>Option 2:</strong> Click the verify button below
                        </p>
                    </div>

                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationLink}"
                           style="background-color: #18c221ff; 
                                  color: white; 
                                  padding: 12px 25px; 
                                  text-decoration: none; 
                                  border-radius: 5px; 
                                  display: inline-block;
                                  font-weight: bold;
                                  box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                            Verify Account
                        </a>
                    </div>

                    <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 20px;">
                        <p style="color: #856404; margin: 0;">
                            <strong>Security Notice:</strong> Both the verification code and link will expire in 10 minutes.
                        </p>
                    </div>

                    <p style="color: #999; font-size: 14px; margin-top: 20px; text-align: center;">
                        If you did not create an account, please ignore this email.
                    </p>
                </div>
            </div>
        `;

        const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
        console.log('Login verification email sent successfully:', response);
        return { success: true, messageId: response.messageId };
    } catch (error) {
        console.error('Error sending login verification email:', error);
        return { success: false, error: error.message };
    }
};

const sendVerificationEmailUser = async (to, subject, recipientName = '', verificationCode = '', verificationLink = '') => {
    try {
        const sendSmtpEmail = new brevo.SendSmtpEmail();
        sendSmtpEmail.sender = {
            name: process.env.SENDER_NAME || 'Art Vista Gallery',
            email: process.env.SENDER_EMAIL || 'noreply@artvista.com'
        };
        sendSmtpEmail.to = [{
            email: to,
            name: recipientName || to.split('@')[0]
        }];
        sendSmtpEmail.subject = subject;
        sendSmtpEmail.htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333; text-align: center;">Art Vista Gallery</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border: 1px solid #007bff;">
                    <h3 style="color: #444;">Hello ${recipientName},</h3>
                    <p style="color: #666;">Thank you for registering with Art Vista Gallery.</p>
                    <p style="color: #666;">Your verification code is: <strong>${verificationCode}</strong></p>
                    <p style="color: #666;">You can also verify your account by clicking the button below:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationLink}"
                           style="background-color: #007bff; 
                                  color: white;
                                    padding: 12px 25px;
                                    text-decoration: none;
                                    border-radius: 5px;
                                    display: inline-block;
                                    font-weight: bold;

                                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);">            
                            Verify Account
                        </a>
                    </div>      
                    <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin-top: 20px;">
                        <p style="color: #856404; margin: 0;">
                            <strong>Security Notice:</strong> Both the verification code and link will expire in 10 minutes.
                        </p>
                    </div>
                    <p style="color: #999; font-size: 14px; margin-top: 20px; text-align: center;">
                        If you did not create an account, please ignore this email.
                    </p>
                </div>
            </div>
        `;

        const response = await apiInstance.sendTransacEmail(sendSmtpEmail);
        console.log('Login verification email sent successfully:', response);
        return { success: true, messageId: response.messageId };
    } catch (error) {
        console.error('Error sending login verification email:', error);
        return { success: false, error: error.message };
    }
};

const verificationSuccess = async (to, subject, recipientName = '') => {
    try {
        const sendSmtpEmail = new brevo.SendSmtpEmail()
        sendSmtpEmail.sender = {
            name: process.env.SENDER_NAME || 'Art Vista Gallery',
            email: process.env.SENDER_EMAIL || 'noreply@artvista.com'
        }
        sendSmtpEmail.to = [{
            email: to,
            name: recipientName || to.split('@')[0]
        }]
        sendSmtpEmail.subject = subject
        sendSmtpEmail.htmlContent = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333; text-align: center;">Art Vista Gallery</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; border: 1px solid #28a745;">
                    <h3 style="color: #444;">Hello ${recipientName},</h3>
                    <div style="background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin
                    <p style="color: #2e7d32; margin: 0;">
                        <strong>Success!</strong> Your email has been verified successfully.
                    </p>
                    </div>
                    <p style="color: #666;">You can now log in and start exploring our collection.</p>
                    <p style="color: #999; font-size: 14px; margin-top: 20px;">Thank you for being a valued member of Art Vista Gallery.</p>
                </div>
            </div>
        `
        const response = await apiInstance.sendTransacEmail(sendSmtpEmail)
        console.log('Verification success email sent successfully:', response)
        return { success: true, messageId: response.messageId }
    } catch (error) {
        console.error('Error sending verification success email:', error)
        return { success: false, error: error.message }

    }
}


export {addProduct,listProducts,deleteProduct, singleProduct, reviewProduct, listPublicProducts, editProduct, addProfile, fetchProfile, sendEmail, sendAdminResetEmail,passwordSuccessEmail, sendLoginVerificationEmail, sendVerificationEmailUser, verificationSuccess}
