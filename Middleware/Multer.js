import multer from 'multer';
import crypto from 'crypto';
import path from 'path';
import { mkdirp } from 'mkdirp';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.join(__dirname, '..', 'uploads');

// Ensure uploads directory exists
await mkdirp(uploadDir);

const storage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, uploadDir);
  },
  filename: function (req, file, callback) {
    // Generate secure filename to prevent path traversal
    const uniqueName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
    const extension = path.extname(file.originalname).toLowerCase();
    callback(null, `${uniqueName}${extension}`);
  }
});

// File filter for security
const fileFilter = (req, file, callback) => {
  // Allow only image files
  const allowedMimeTypes = [
    'image/jpeg',
    'image/jpg', 
    'image/png',
    'image/gif',
    'image/webp'
  ];
  
  if (allowedMimeTypes.includes(file.mimetype)) {
    callback(null, true);
  } else {
    callback(new Error('Invalid file type. Only image files are allowed.'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit per file
    files: 4 // Maximum 4 files per request
  },
  fileFilter: fileFilter
});

export default upload;
