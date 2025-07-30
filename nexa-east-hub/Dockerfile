# Use Node.js official image
FROM node:18

# Create app directory
WORKDIR /app

# Copy dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of your app
COPY . .

# Set environment port
ENV PORT=3000
EXPOSE 3000

CMD [ "npm", "start" ]
