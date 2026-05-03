import { payment } from "../DB/model.js"
import express from "express"
import Stripe from 'stripe';
import dotenv from 'dotenv';
import userAuth from "../Middleware/userAuth.js";
import adminAuth from "../Middleware/adminAuth.js";
import { FinancialAuditLog } from "../security-fixes/soc-controls.js";

dotenv.config();

const payments = express.Router();
const stripe = new Stripe(process.env.STRIPE_API_KEY);

// Create Payment Intent
payments.post('/create-payment-intent', userAuth, async (req, res) => {
    try {
        const { amount, currency = 'sgd', items, shippingAddress } = req.body;
        const userId = req.user.id; // use verified identity, not user-supplied value

        if (!amount || !items) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: userId, amount, items'
            });
        }

        // Create payment intent with Stripe
        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(amount * 100), 
            currency: currency.toLowerCase(),
            metadata: {
                userId,
                itemCount: items.length.toString()
            }
        });

        // Save payment record to database
        const newPayment = new payment({
            userId,
            orderId: paymentIntent.id,
            amount,
            currency: currency.toUpperCase(),
            paymentMethod: 'stripe',
            // ✅ Fixed: Use paymentIntent.status instead of undefined stripeStatus
            paymentStatus: getInitialPaymentStatus(paymentIntent.status),
            transactionId: paymentIntent.id,
            items,
            shippingAddress
        });

        await newPayment.save();

        // Log financial event
        try {
            await FinancialAuditLog.create({
                userId,
                transactionId: paymentIntent.id,
                type: 'Payment',
                amount,
                currency: currency.toUpperCase(),
                status: 'PENDING',
                timestamp: new Date(),
                metadata: {
                    itemCount: items.length,
                    paymentMethod: 'stripe'
                }
            });
        } catch (logError) {
            console.error('Failed to log financial event:', logError.message);
        }

        res.json({
            success: true,
            clientSecret: paymentIntent.client_secret,
            paymentId: newPayment._id,
            orderId: paymentIntent.id
        });

    } catch (error) {
        console.error('Error creating payment intent:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create payment intent',
            error: error.message
        });
    }
});

// Replace your getInitialPaymentStatus function with this:
function getInitialPaymentStatus(stripeStatus) {
    return 'pending'; // Always start as pending, let webhook update to succeeded
}

// Confirm Payment
payments.post('/confirm-payment', async (req, res) => {
    try {
        const { paymentIntentId, paymentMethodId } = req.body;

        const paymentIntent = await stripe.paymentIntents.confirm(paymentIntentId, {
            payment_method: paymentMethodId
        });

        // ✅ More detailed status handling
        let newStatus = 'pending';
        if (paymentIntent.status === 'succeeded') {
            newStatus = 'succeeded';
        } else if (paymentIntent.status === 'requires_action') {
            newStatus = 'pending';
        } else if (paymentIntent.status === 'processing') {
            newStatus = 'processing';
        } else {
            newStatus = 'failed';
        }

        const updatedPayment = await payment.findOneAndUpdate(
            { transactionId: paymentIntentId },
            { 
                paymentStatus: newStatus,
                updatedAt: new Date()
            },
            { new: true }
        );

        // Update financial audit log status
        if (updatedPayment && newStatus === 'succeeded') {
            try {
                await FinancialAuditLog.findOneAndUpdate(
                    { transactionId: paymentIntentId },
                    { 
                        status: 'SUCCEEDED',
                        timestamp: new Date()
                    }
                );
                console.log('✅ Financial audit log updated to SUCCEEDED (confirm-payment)');
            } catch (logError) {
                console.error('Failed to update financial audit log:', logError.message);
            }
        } else if (updatedPayment && newStatus === 'failed') {
            try {
                await FinancialAuditLog.findOneAndUpdate(
                    { transactionId: paymentIntentId },
                    { 
                        status: 'FAILED',
                        timestamp: new Date()
                    }
                );
                console.log('✅ Financial audit log updated to FAILED (confirm-payment)');
            } catch (logError) {
                console.error('Failed to update financial audit log:', logError.message);
            }
        }

        console.log('Payment status updated to:', newStatus); // ✅ Add logging

        res.json({
            success: true,
            paymentStatus: paymentIntent.status,
            payment: updatedPayment
        });

    } catch (error) {
        console.error('Error confirming payment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to confirm payment',
            error: error.message
        });
    }
});

// Webhook endpoint for Stripe events
payments.post('/webhook', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        // ✅ Now req.body should be raw buffer
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
        console.log('📨 Webhook received:', event.type);
        console.log('💳 Payment Intent ID:', event.data.object.id);
    } catch (err) {
        console.error('❌ Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Get io instance from app
    const io = req.app.get('io');

    // Handle the event
    switch (event.type) {
        case 'payment_intent.succeeded':
            const paymentIntent = event.data.object;
            console.log('💰 Updating payment to succeeded:', paymentIntent.id);
            
            const updatedPayment = await payment.findOneAndUpdate(
                { transactionId: paymentIntent.id },
                { paymentStatus: 'succeeded', updatedAt: new Date() },
                { new: true }
            );
            
            // Update financial audit log to SUCCEEDED
            if (updatedPayment) {
                try {
                    await FinancialAuditLog.findOneAndUpdate(
                        { transactionId: paymentIntent.id },
                        { 
                            status: 'SUCCEEDED',
                            timestamp: new Date()
                        }
                    );
                    console.log('✅ Financial audit log updated to SUCCEEDED');
                } catch (logError) {
                    console.error('Failed to update financial audit log:', logError.message);
                }
            }
            
            // Send real-time update to frontend
            if (updatedPayment && io) {
                const statusUpdate = {
                    orderId: updatedPayment.orderId,
                    transactionId: updatedPayment.transactionId,
                    paymentStatus: 'succeeded',
                    payment: updatedPayment,
                    userId: updatedPayment.userId,
                    timestamp: new Date().toISOString()
                };
                
                io.emit('payment_status_update', statusUpdate);
                console.log('🚀 Payment status broadcasted to frontend:', statusUpdate.orderId);
            }
            
            console.log('✅ Payment updated:', updatedPayment);
            break;

        case 'payment_intent.payment_failed':
            const failedPayment = event.data.object;
            console.log('❌ Payment failed:', failedPayment.id);
            
            const failedRecord = await payment.findOneAndUpdate(
                { transactionId: failedPayment.id },
                { paymentStatus: 'failed', updatedAt: new Date() },
                { new: true }
            );
            
            // Update financial audit log to FAILED
            if (failedRecord) {
                try {
                    await FinancialAuditLog.findOneAndUpdate(
                        { transactionId: failedPayment.id },
                        { 
                            status: 'FAILED',
                            timestamp: new Date()
                        }
                    );
                    console.log('✅ Financial audit log updated to FAILED');
                } catch (logError) {
                    console.error('Failed to update financial audit log:', logError.message);
                }
            }
            
            // Send failure update to frontend
            if (failedRecord && io) {
                const failureUpdate = {
                    orderId: failedRecord.orderId,
                    transactionId: failedRecord.transactionId,
                    paymentStatus: 'failed',
                    payment: failedRecord,
                    userId: failedRecord.userId,
                    timestamp: new Date().toISOString()
                };
                
                io.emit('payment_status_update', failureUpdate);
                console.log('🚀 Payment failure broadcasted to frontend:', failureUpdate.orderId);
            }
            break;

        default:
            console.log(`❓ Unhandled event type ${event.type}`);
    }

    res.json({received: true});
});

// Get payment by ID
payments.get('/payment/:orderId', async (req, res) => {
    try {
        // Fixed: Use findOne with orderId instead of findById
        const paymentRecord = await payment.findOne({ orderId: req.params.orderId })
            .populate('userId', 'name email')
            .populate('items.productId', 'productName Price Image');

        // If not found by orderId, try by _id (in case it's a MongoDB ObjectId)
        if (!paymentRecord) {
            try {
                const paymentById = await payment.findById(req.params.orderId)
                    .populate('userId', 'name email')
                    .populate('items.productId', 'productName Price Image');
                
                if (paymentById) {
                    return res.json({
                        success: true,
                        payment: paymentById
                    });
                }
            } catch (err) {
                // Not a valid ObjectId, continue with not found
            }
        }

        if (!paymentRecord) {
            return res.status(404).json({
                success: false,
                message: 'Payment not found'
            });
        }

        res.json({
            success: true,
            payment: paymentRecord
        });

    } catch (error) {
        console.error('Error fetching payment:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment',
            error: error.message
        });
    }
});

// Get user payments
payments.get('/user/:userId', userAuth, async (req, res) => {
    if (req.user.id !== req.params.userId) {
        return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    try {
        const userPayments = await payment.find({ userId: req.params.userId })
            .populate('items.productId', 'productName Price Image') // Removed extra space after Image
            .sort({ createdAt: -1 });

        res.json({
            success: true,
            payments: userPayments
        });

    } catch (error) {
        console.error('Error fetching user payments:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payments',
            error: error.message
        });
    }
});

// Refund payment
payments.post('/refund', adminAuth, async (req, res) => {
    try {
        const { paymentIntentId, amount, reason } = req.body;

        const refund = await stripe.refunds.create({
            payment_intent: paymentIntentId,
            amount: amount ? Math.round(amount * 100) : undefined, // Partial or full refund
            reason: reason || 'requested_by_customer'
        });

        // Update payment status
        await payment.findOneAndUpdate(
            { transactionId: paymentIntentId },
            { 
                paymentStatus: 'refunded',
                updatedAt: new Date()
            }
        );

        res.json({
            success: true,
            refund: refund
        });

    } catch (error) {
        console.error('Error processing refund:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to process refund',
            error: error.message
        });
    }
});

payments.get('/order-details/:id', async (req, res) => {
    try {
        const orderId = req.params.id; // Make sure this matches the parameter
        
        // Try to find by orderId first, then by _id
        let order = await payment.findOne({ orderId: orderId })
            .populate('items.productId', 'productName Price Image')
            .populate('userId', 'name email');
            
        // If not found by orderId, try by _id
        if (!order) {
            order = await payment.findById(orderId)
                .populate('items.productId', 'productName Price Image')
                .populate('userId', 'name email');
        }
        
        if (!order) {
            return res.status(404).json({ 
                success: false, 
                message: 'Order not found' 
            });
        }

        res.json({
            success: true,
            order: order
        });

    } catch (error) {
        console.error('Error fetching order details:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch order details',
            error: error.message
        });
    }
});

payments.get('/status/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;
        const paymentRecord = await payment.findOne({ orderId });

        if (!paymentRecord) {
            return res.status(404).json({
                success: false,
                message: 'Payment not found'
            });
        }   
        res.json({
            success: true,
            paymentStatus: paymentRecord.paymentStatus
        });
    } catch (error) {
        console.error('Error fetching payment status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch payment status',  
            error: error.message
        });
    }
});

// In Payments.js - Add endpoint to check payment status
payments.get('/check-status/:paymentIntentId', async (req, res) => {
    try {
        const { paymentIntentId } = req.params;
        
        // Get current status from database
        const paymentRecord = await payment.findOne({ 
            transactionId: paymentIntentId 
        });

        if (!paymentRecord) {
            return res.status(404).json({
                success: false,
                message: 'Payment not found'
            });
        }

        res.json({
            success: true,
            paymentStatus: paymentRecord.paymentStatus,
            payment: paymentRecord
        });

    } catch (error) {
        console.error('Error checking payment status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to check payment status',
            error: error.message
        });
    }
});

payments.post('/reorder/:orderId', userAuth, async (req, res) => {
    try {
        const { orderId } = req.params;
        const originalOrder = await payment.findOne({ orderId });

        if (!originalOrder) {
            return res.status(404).json({
                success: false,
                message: 'Original order not found'
            });
        }

        // Generate a unique orderId for the reorder
        const newOrderId = `reorder_${Date.now()}_${originalOrder._id}`;

        const newOrder = new payment({
            userId: originalOrder.userId,
            orderId: newOrderId,
            amount: originalOrder.amount,
            currency: originalOrder.currency,
            paymentMethod: originalOrder.paymentMethod || 'stripe',
            paymentStatus: 'pending',
            items: originalOrder.items,
            shippingAddress: originalOrder.shippingAddress
        });

        await newOrder.save();

        res.json({
            success: true,
            message: 'Order reprocessed successfully',
            order: newOrder
        });

    } catch (error) {
        console.error('Error reprocessing order:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reorder',
            error: error.message
        });
    }
});     


export default payments;