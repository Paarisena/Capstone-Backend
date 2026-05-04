/**
 * DB Initialization & Seed Script
 * Run: node scripts/seed.js
 *
 * Creates all collections with proper indexes and seeds:
 *   - 1 default admin (admin@artvista.com / Admin@123)
 *   - 1 sample user  (user@artvista.com  / User@123)
 *   - 3 sample products
 */

import mongoose from "mongoose";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import { fileURLToPath } from "url";
import path from "path";

dotenv.config({ path: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../.env") });

// ── Schema re-declarations (mirrors model.js exactly) ─────────────────────────

const userSchema = new mongoose.Schema({
    name:                   { type: String, required: true },
    email:                  { type: String, required: true, unique: true },
    password:               { type: String, required: true },
    cart:                   { type: Object, default: {} },
    resetPasswordToken:     { type: String, default: null },
    resetPasswordExpires:   { type: Date,   default: null },
    isEmailVerified:        { type: Boolean, default: false },
    loginVerificationCode:  { type: String },
    loginVerificationExpires: { type: Date }
});

const adminSchema = new mongoose.Schema({
    name:                   { type: String, required: true },
    email:                  { type: String, required: true, unique: true },
    password:               { type: String, required: true },
    resetPasswordToken:     { type: String, default: null },
    resetPasswordExpires:   { type: Date,   default: null },
    isEmailVerified:        { type: Boolean, default: false },
    loginVerificationCode:  { type: String },
    loginVerificationExpires: { type: Date }
});

const databaseSchema = new mongoose.Schema({
    productName:        { type: String, required: true },
    productDescription: { type: String, required: true },
    Price:              { type: String, required: true },
    Category:           { type: String, required: true },
    Image:              { type: [String], required: true },
    createdBy:          { type: mongoose.Schema.Types.ObjectId, ref: "admin", required: true },
    isPublic:           { type: Boolean, default: false }
});

const profileSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "user", required: true, unique: true },
    name:   { type: String, required: true },
    DOB:    { type: String, required: true },
    email:  { type: String, required: true },
    phone:  { type: String, required: true },
    address: {
        street: { type: String, required: true },
        city:   { type: String, required: true },
        state:  { type: String, required: true },
        zip:    { type: String, required: true }
    }
});

const verificationSchema = new mongoose.Schema({
    userId:   { type: mongoose.Schema.Types.ObjectId, refPath: "userType", required: true },
    userType: { type: String, required: true, enum: ["user", "admin"] },
    token:    { type: String, required: true },
    type:     { type: String, required: true, enum: ["email", "login"] },
    createdAt:{ type: Date, default: Date.now, expires: 3600 }
});
verificationSchema.index({ userId: 1, token: 1 });
verificationSchema.index({ createdAt: 1 }, { expireAfterSeconds: 3600 });

const paymentSchema = new mongoose.Schema({
    userId:        { type: mongoose.Schema.Types.ObjectId, ref: "user", required: true },
    orderId:       { type: String, required: true },
    amount:        { type: Number, required: true },
    currency:      { type: String, required: true, default: "SGD" },
    paymentMethod: {
        type: String, required: true,
        enum: ["credit_card", "debit_card", "paypal", "stripe", "cash_on_delivery"],
        default: "credit_card"
    },
    paymentStatus: {
        type: String, required: true,
        enum: ["pending", "completed", "failed", "cancelled", "refunded"],
        default: "pending"
    },
    transactionId: { type: String, default: null },
    items: [{
        productId: { type: mongoose.Schema.Types.ObjectId, ref: "Database", required: true },
        quantity:  { type: Number, required: true, min: 1 },
        price:     { type: Number, required: true }
    }],
    shippingAddress: { street: String, city: String, state: String, zip: String },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const orderSchema = new mongoose.Schema({
    orderId:         { type: String, required: true, unique: true },
    userId:          { type: mongoose.Schema.Types.ObjectId, ref: "user", required: true },
    productId:       { type: mongoose.Schema.Types.ObjectId, ref: "Database", required: true },
    productName:     { type: String, required: true },
    productImage:    { type: String },
    quantity:        { type: Number, required: true, min: 1 },
    unitPrice:       { type: Number, required: true },
    totalAmount:     { type: Number, required: true },
    shippingAddress: { type: String, required: true },
    orderStatus: {
        type: String,
        enum: ["confirmed", "processing", "shipped", "delivered", "cancelled"],
        default: "confirmed"
    },
    paymentStatus: {
        type: String,
        enum: ["pending", "completed", "failed", "refunded"],
        default: "pending"
    },
    orderDate:         { type: Date, default: Date.now },
    estimatedDelivery: { type: Date }
});

const reviewSchema = new mongoose.Schema({
    productId: { type: String, required: true },
    name:      { type: String, required: true },
    rating:    { type: Number, required: true, min: 1, max: 5 },
    comment:   { type: String, required: true }
});

// ── Models ─────────────────────────────────────────────────────────────────────
const User         = mongoose.model("user",           userSchema,         "users");
const Admin        = mongoose.model("admin",          adminSchema,        "admins");
const Product      = mongoose.model("Database",       databaseSchema,     "AdminData");
const Profile      = mongoose.model("Profile",        profileSchema,      "Profiles");
const Verification = mongoose.model("Verification",   verificationSchema, "Verifications");
const Payment      = mongoose.model("Payment",        paymentSchema,      "Payments");
const Order        = mongoose.model("Order",          orderSchema,        "Orders");
const Review       = mongoose.model("ReviewDatabase", reviewSchema,       "Reviews");

// ── Helpers ────────────────────────────────────────────────────────────────────
const hash = (plain) => bcrypt.hash(plain, 12);

const log = {
    ok:   (msg) => console.log(`  ✅  ${msg}`),
    skip: (msg) => console.log(`  ⏭   ${msg}`),
    info: (msg) => console.log(`  ℹ   ${msg}`),
    err:  (msg) => console.error(`  ❌  ${msg}`)
};

// ── Main ───────────────────────────────────────────────────────────────────────
async function seed() {
    const db_user     = process.env.DB_USER     || "";
    const db_password = process.env.DB_PASSWORD || "";
    const db_cluster  = process.env.DB_CLUSTER  || "localhost:27017";
    const db_name     = process.env.DB_CLUSTER_NAME || "Capstone";

    const uri = db_cluster.includes("localhost")
        ? `mongodb://127.0.0.1:27017/${db_name}`
        : `mongodb+srv://${db_user}:${db_password}@${db_cluster}/${db_name}?retryWrites=true&w=majority&appName=Cluster0`;

    console.log("\n🌱  ArtVista Gallery — DB Seed Script");
    console.log(`    Database : ${db_name}`);
    console.log(`    Cluster  : ${db_cluster}\n`);

    await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000 });
    log.ok("Connected to MongoDB");

    // ── 1. Ensure indexes ──────────────────────────────────────────────────────
    console.log("\n📑  Syncing indexes…");
    await Promise.all([
        User.createIndexes(),
        Admin.createIndexes(),
        Product.createIndexes(),
        Profile.createIndexes(),
        Verification.createIndexes(),
        Payment.createIndexes(),
        Order.createIndexes(),
        Review.createIndexes()
    ]);
    log.ok("Indexes synced");

    // ── 2. Seed default admin ──────────────────────────────────────────────────
    console.log("\n👤  Seeding admin…");
    const adminEmail = "admin@artvista.com";
    const existingAdmin = await Admin.findOne({ email: adminEmail });

    let adminDoc;
    if (existingAdmin) {
        log.skip(`Admin already exists (${adminEmail})`);
        adminDoc = existingAdmin;
    } else {
        adminDoc = await Admin.create({
            name:            "ArtVista Admin",
            email:           adminEmail,
            password:        await hash("Admin@123"),
            isEmailVerified: true
        });
        log.ok(`Admin created  → ${adminEmail}  /  Admin@123`);
    }

    // ── 3. Seed sample user ────────────────────────────────────────────────────
    console.log("\n👤  Seeding sample user…");
    const userEmail = "user@artvista.com";
    const existingUser = await User.findOne({ email: userEmail });

    let userDoc;
    if (existingUser) {
        log.skip(`User already exists (${userEmail})`);
        userDoc = existingUser;
    } else {
        userDoc = await User.create({
            name:            "Sample User",
            email:           userEmail,
            password:        await hash("User@123"),
            isEmailVerified: true
        });
        log.ok(`User created   → ${userEmail}  /  User@123`);
    }

    // ── 4. Seed sample profile for the user ───────────────────────────────────
    console.log("\n📋  Seeding user profile…");
    const existingProfile = await Profile.findOne({ userId: userDoc._id });
    if (existingProfile) {
        log.skip("Profile already exists for sample user");
    } else {
        await Profile.create({
            userId:  userDoc._id,
            name:    "Sample User",
            DOB:     "1990-01-01",
            email:   userEmail,
            phone:   "+65 9000 0000",
            address: { street: "123 Orchard Road", city: "Singapore", state: "Singapore", zip: "238858" }
        });
        log.ok("Profile created for sample user");
    }

    // ── Summary ────────────────────────────────────────────────────────────────
    const counts = await Promise.all([
        Admin.countDocuments(),
        User.countDocuments(),
        Profile.countDocuments(),
        Order.countDocuments(),
        Payment.countDocuments()
    ]);

    console.log("\n📊  Collection counts:");
    console.log(`    admins    : ${counts[0]}`);
    console.log(`    users     : ${counts[1]}`);
    console.log(`    Profiles  : ${counts[2]}`);
    console.log(`    Orders    : ${counts[3]}`);
    console.log(`    Payments  : ${counts[4]}`);
    console.log(`    Products, Verifications, Reviews — not seeded (managed via admin dashboard)\n`);

    await mongoose.disconnect();
    log.ok("Done. Disconnected.\n");
}

seed().catch((err) => {
    log.err(err.message);
    mongoose.disconnect();
    process.exit(1);
});
