import { CloudinaryStorage } from "multer-storage-cloudinary";
import multer from "multer";
import { cloudinary } from "../config";

// Define types for resource types and allowed formats
type ResourceType = "image" | "video";
type AllowedFormats = "jpg" | "jpeg" | "png" | "gif" | "mp4" | "mov" | "avi" | "mkv" | "pdf";

// Dynamic configuration for multer and Cloudinary
const configureCloudinaryStorage = ({
  fieldName,
  folder,
  resourceType,
  allowedFormats,
  overwrite = false,
}: {
  fieldName: string;
  folder: string;
  resourceType: ResourceType;
  allowedFormats: AllowedFormats[];
  overwrite: boolean;
}) => {
  return new CloudinaryStorage({
    cloudinary,
    params: async (req) => {
      const userId = req.user?.sub || "guest"; // Default to "guest" if no user

      // Generate a custom filename
      const originalName = req.file?.originalname || "file";
      const timestamp = Date.now();
      const sanitizedFilename = originalName.replace(/\s+/g, "_").toLowerCase();

      // Logic for filename when overwriting is enabled
      const filename = overwrite
      ? `${fieldName}_${userId}`
      : `${sanitizedFilename}_${timestamp}`;
      
      return {
        folder: `${folder}/${userId}`, // Organize uploads by user ID
        resource_type: resourceType,
        allowed_formats: allowedFormats,
        use_filename: true, // Use the custom filename
        unique_filename: !overwrite, // Ensure this is false if overwriting
        filename:  filename, // Custom filename logic
        overwrite: overwrite, // Ensure overwrite is true to allow replacement
      };
    },
  });
};

// Middleware factory for dynamic upload
const cloudinaryUpload = {
  Image: ({
    fieldName,
    folder = "uploads/images",
    overwrite = false,
  }: {
    fieldName: string;
    folder: string;
    overwrite: boolean;
  }) =>
    multer({
      storage: configureCloudinaryStorage({
        fieldName:fieldName,
        folder: folder,
        resourceType: "image",
        allowedFormats: ["jpg", "jpeg", "png", "gif"],
        overwrite: overwrite,
      }),
    }).single(fieldName),

  Video: ({
    fieldName,
    folder = "uploads/videos",
    overwrite = false,
  }: {
    fieldName: string;
    folder: string;
    overwrite: boolean;
  }) =>
    multer({
      storage: configureCloudinaryStorage({
        fieldName: fieldName,
        folder: folder,
        resourceType: "video",
        allowedFormats: ["mp4", "mov", "avi", "mkv"],
        overwrite: overwrite,
      }),
    }).single(fieldName),
};

export default cloudinaryUpload;
