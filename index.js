'use strict';

console.log('🚀 Starting application via iisnode...');
import('./server.js')
    .then(() => console.log('✅ Server started successfully'))
    .catch(err => {
        console.error('❌ Failed to start server:', err);
        process.exit(1);
        
    });