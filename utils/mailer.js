const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'pikelelalikho@gmail.com',
        pass: process.env.EMAIL_PASS
    }
});
