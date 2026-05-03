import jwt from 'jsonwebtoken';
import { user } from '../DB/model.js';
import dotenv from 'dotenv';

dotenv.config();

const userAuth = async (req, res, next) => {
    try {
        const token = req.cookies?.authToken || req.header('Authorization')?.replace('Bearer ', '');

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access denied. No token provided.'
            });
        }

        const decoded = jwt.verify(token, process.env.SECRET_TOKEN);

        const foundUser = await user.findById(decoded.id);

        if (!foundUser || !foundUser.isEmailVerified) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or unverified user.'
            });
        }

        req.user = {
            id: foundUser._id.toString(),
            email: foundUser.email,
            name: foundUser.name,
            isAdmin: false
        };

        next();
    } catch (error) {
        res.status(401).json({
            success: false,
            message: 'Invalid token.'
        });
    }
};

export default userAuth;
