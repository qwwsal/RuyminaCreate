const AWS = require('aws-sdk');
const fs = require('fs');
const path = require('path');

// Настройка S3 клиента для Yandex Cloud
const s3 = new AWS.S3({
    endpoint: 'https://storage.yandexcloud.net',
    region: 'ru-central1',
    accessKeyId: process.env.YC_ACCESS_KEY_ID,
    secretAccessKey: process.env.YC_SECRET_ACCESS_KEY
});

const uploadToYandex = async (filePath, originalName) => {
    try {
        console.log('📤 Uploading to Yandex Cloud...', filePath);
        
        const fileContent = fs.readFileSync(filePath);
        const fileName = `portfolio/${Date.now()}-${originalName}`;
        
        const params = {
            Bucket: process.env.YC_BUCKET_NAME,
            Key: fileName,
            Body: fileContent,
            ACL: 'public-read',
            ContentType: getContentType(originalName)
        };
        
        const result = await s3.upload(params).promise();
        console.log('✅ Upload successful:', result.Location);
        
        // Удаляем временный файл
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        
        return result.Location;
    } catch (error) {
        console.error('❌ Yandex Cloud upload error:', error);
        
        // Очищаем временный файл даже при ошибке
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
        
        throw error;
    }
};

// Функция для определения типа контента
function getContentType(filename) {
    const ext = path.extname(filename).toLowerCase();
    const types = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.webp': 'image/webp'
    };
    return types[ext] || 'application/octet-stream';
}

module.exports = { uploadToYandex };