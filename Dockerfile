FROM node:18

WORKDIR /app

# Copy package files and install
COPY package*.json ./
RUN npm install

# Copy everything else
COPY . .

# Hugging Face uses port 7860
ENV PORT=7860
EXPOSE 7860

CMD ["node", "server.js"]