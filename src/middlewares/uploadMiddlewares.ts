import multer from "multer";
import path from "path";

// Factory function to configure Multer for specific file types
const fileUpload = ({
  uploadFolder = "uploads",      // Folder to temporarily store files
  allowedMimeTypes = ["image/"], // Array of allowed MIME types
  maxFileSizeMB = 5,             // File size limit in MB
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fileFilter = (_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
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
  uploadFolder: "uploads/images",
  allowedMimeTypes: ["image/"], // Only images (e.g., image/png, image/jpeg)
  maxFileSizeMB: 5,
});

// Upload configuration for PDFs
const pdfUpload = fileUpload({
  uploadFolder: "uploads/documents",
  allowedMimeTypes: ["application/pdf"], // Only PDF files
  maxFileSizeMB: 10,
});

// Upload configuration for PDFs
const jsonUpload = fileUpload({
    uploadFolder: "uploads/json",
    allowedMimeTypes: ["application/json"], // Only json files
    maxFileSizeMB: 10,
  });

export { imageUpload, pdfUpload, jsonUpload };
