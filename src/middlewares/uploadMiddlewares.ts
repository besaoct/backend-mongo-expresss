import multer from "multer";
import path from "path";
import fs from "fs";
import { Request } from "express";

// Ensure upload directories exist
const ensureUploadDirectoriesExist = () => {

  const uploadPaths = [
    path.join(__dirname, "../../public/uploads/images"),
    path.join(__dirname, "../../public/uploads/docs"),
    path.join(__dirname, "../../public/uploads/json"),
    path.join(__dirname, "../../public/uploads/videos"),
    path.join(__dirname, "../../public/uploads/audio"),
    path.join(__dirname, "../../public/uploads/archives"),
    path.join(__dirname, "../../public/uploads/misc"),
  ];


  uploadPaths.forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true }); // Ensure parent directories are created
    }
  });

  
};

// Factory function to configure Multer for specific file types
const fileUpload = ({
  uploadFolder = "public/uploads/misc", // Folder to temporarily store files
  allowedMimeTypes = [
    "image/", // Image files
    "video/", // Video files
    "audio/", // Audio files
    "application/pdf", // PDFs
    "application/json", // JSON files
    "application/zip", "application/x-tar", "application/gzip", // Archives
    "application/octet-stream", // Accept Blob data (binary data)
  ], // Array of allowed MIME types
  maxFileSizeMB = 100, // File size limit in MB
}) => {
  // Set up storage (temporarily stores files on disk)
  const storage = multer.diskStorage({
    destination: (_req, _file, cb) => {
      cb(null, path.join(__dirname, `../${uploadFolder}`)); // Dynamic upload folder
    },
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname);
      const baseName = file.fieldname.replace(/\s+/g, "_"); // Sanitize field name
      cb(null, `${Date.now()}-${baseName}${ext}`); // Unique file name
    },
  });

  // File filter for allowed MIME types
  const fileFilter = (_req: Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const isAllowed = allowedMimeTypes.some((type) => file.mimetype.startsWith(type));
    if (isAllowed) {
      cb(null, true);
    } else {
      cb(new Error(`Only ${allowedMimeTypes.join(", ")} files are allowed!`));
    }
  };

  // Multer configuration
  return multer({
    storage,
    fileFilter,
    limits: { fileSize: maxFileSizeMB * 1024 * 1024 }, // Convert MB to bytes
  });
};

// Upload configuration for images
const imageUpload = fileUpload({
  uploadFolder: "public/uploads/images",
  allowedMimeTypes: ["image/"], // Only images (e.g., image/png, image/jpeg)
  maxFileSizeMB: 5,
});

// Upload configuration for PDFs
const pdfUpload = fileUpload({
  uploadFolder: "public/uploads/docs",
  allowedMimeTypes: ["application/pdf"], // Only PDF files
  maxFileSizeMB: 10,
});

// Upload configuration for JSON
const jsonUpload = fileUpload({
  uploadFolder: "public/public/uploads/json",
  allowedMimeTypes: ["application/json"], // Only JSON files
  maxFileSizeMB: 10,
});

// Upload configuration for videos
const videoUpload = fileUpload({
  uploadFolder: "public/uploads/videos",
  allowedMimeTypes: ["video/"], // Only video files (e.g., video/mp4, video/mkv)
  maxFileSizeMB: 50,
});

// Upload configuration for audio
const audioUpload = fileUpload({
  uploadFolder: "public/uploads/audio",
  allowedMimeTypes: ["audio/"], // Only audio files (e.g., audio/mp3, audio/wav)
  maxFileSizeMB: 20,
});

// Upload configuration for archives
const archiveUpload = fileUpload({
  uploadFolder: "public/uploads/archives",
  allowedMimeTypes: ["application/zip", "application/x-tar", "application/gzip"], // Only archive files
  maxFileSizeMB: 100,
});

// misc Upload configuration to accept all file types
const miscUpload = fileUpload({
  uploadFolder: "public/uploads/misc", // All types go into the misc folder
  allowedMimeTypes: [
    "image/", // Image files
    "video/", // Video files
    "audio/", // Audio files
    "application/pdf", // PDFs
    "application/json", // JSON files
    "application/zip", "application/x-tar", "application/gzip", // Archives
    "application/octet-stream", // Accept Blob data (binary data)
  ], 
  maxFileSizeMB: 100, // Max file size for any upload type (you can adjust this as needed)
});

export { ensureUploadDirectoriesExist, imageUpload, pdfUpload, jsonUpload, videoUpload, audioUpload, archiveUpload, miscUpload};
