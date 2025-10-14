import jwt from 'jsonwebtoken';
import { admin } from '../DB/model.js';

const adminAuth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
        }

        const decoded = jwt.verify(token, process.env.SECRET_TOKEN);
        const adminUser = await admin.findById(decoded.id);

        if (!adminUser || adminUser.isVerified === false) {
            return res.status(401).json({ success: false, message: 'Invalid or unverified admin.' });
        }

        req.user = {
            id: adminUser._id.toString(),
            email: adminUser.email,
            name: adminUser.name,
            isAdmin: true
        };

        next();
    } catch (error) {
        console.error('AdminAuth error:', error);
        const message = error.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token';
        res.status(401).json({ success: false, message });
    }
};

export default adminAuth;