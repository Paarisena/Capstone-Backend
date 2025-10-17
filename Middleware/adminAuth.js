import jwt from 'jsonwebtoken';
import { user, admin } from '../DB/model.js';
import dotenv from 'dotenv';

dotenv.config();

const adminAuth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'Access denied. No token provided.' 
            });
        }

        const decoded = jwt.verify(token, process.env.SECRET_TOKEN);
        
        // Try to find user in both admin and user collections
        let foundUser = await admin.findById(decoded.id);
        let isAdmin = true;
        
        if (!foundUser) {
            foundUser = await user.findById(decoded.id);
            isAdmin = false;
        }

        if (!foundUser || foundUser.isVerified === false) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid or unverified user.' 
            });
        }

        req.user = {
            id: foundUser._id.toString(),
            email: foundUser.email,
            name: foundUser.name,
            isAdmin
        };

        next();
    } catch (error) {
        console.error('FlexAuth error:', error);
        res.status(401).json({ 
            success: false, 
            message: 'Invalid token.' 
        });
    }
};

export default adminAuth;