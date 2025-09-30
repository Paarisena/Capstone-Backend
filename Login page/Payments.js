import { payment } from "../DB/model.js"
import express from "express"
import Stripe from 'stripe';
import dotenv from 'dotenv';

dotenv.config();

const payments = express.Router();
const stripe = new Stripe(process.env.STRIPE_API_KEY);

// Create Payment Intent
payments.post('/create-payment-intent', async (req, res) => {
    try {
        const {userId, amount, currency = 'sgd', items, shippingAddress } = req.body;
        

        if (!userId || !amount || !items) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: userId, amount, items'
            });
        }

        // Create payment intent with Stripe
        const paymentIntent = await stripe.paymentIntents.create({
            amount: Math.round(amount * 100), // Stripe expects cents
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
            paymentStatus: 'pending',
            transactionId: paymentIntent.id,
            items,
            shippingAddress
        });

        await newPayment.save();

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

// Confirm Payment
payments.post('/confirm-payment', async (req, res) => {
    try {
        const { paymentIntentId, paymentMethodId } = req.body;

        // Confirm payment with Stripe
        const paymentIntent = await stripe.paymentIntents.confirm(paymentIntentId, {
            payment_method: paymentMethodId
        });

        // Update payment status in database
        const updatedPayment = await payment.findOneAndUpdate(
            { transactionId: paymentIntentId },
            { 
                paymentStatus: paymentIntent.status === 'succeeded' ? 'completed' : 'failed',
                updatedAt: new Date()
            },
            { new: true }
        );

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
payments.post('/webhook', express.raw({type: 'application/json'}), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the event
    switch (event.type) {
        case 'payment_intent.succeeded':
            const paymentIntent = event.data.object;
            await payment.findOneAndUpdate(
                { transactionId: paymentIntent.id },
                { paymentStatus: 'completed', updatedAt: new Date() }
            );
            console.log('Payment succeeded:', paymentIntent.id);
            break;

        case 'payment_intent.payment_failed':
            const failedPayment = event.data.object;
            await payment.findOneAndUpdate(
                { transactionId: failedPayment.id },
                { paymentStatus: 'failed', updatedAt: new Date() }
            );
            console.log('Payment failed:', failedPayment.id);
            break;

        default:
            console.log(`Unhandled event type ${event.type}`);
    }

    res.json({received: true});
});

// Get payment by ID
payments.get('/payment/:id', async (req, res) => {
    try {
        const paymentRecord = await payment.findById(req.params.id)
            .populate('userId', 'name email')
            .populate('items.productId', 'productName, Price');

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
payments.get('/user/:userId', async (req, res) => {
    // const user = req.params.userId;
    try {
        const userPayments = await payment.find({ userId: req.params.userId })
            .populate('items.productId', 'productName Price Image ')
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
payments.post('/refund', async (req, res) => {
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

export default payments;