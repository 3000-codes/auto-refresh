import ssh2 from "ssh2";
import nodemailer from "nodemailer";

const {
  S_HOST, // Server Host
  S_NAME, // Server Name
  S_PWD, // Server Password
  C_SCT, // Cron Secret
  U_EMAIL, // User Email
  U_SMTP, // User SMTP Code
} = process.env;

export default async function handler(req, res) {
  const { authorization } = req.headers;
  if (authorization?.startsWith("Bearer ")) {
    if (authorization.substring(7) === C_SCT) return sshConnect(res);
    return res.status(401).json({ status: "error", error: "Invalid Secret" });
  }
  if (validate(authorization)) return sshConnect(res);

  res.setHeader("WWW-Authenticate", 'Basic realm="Secure Area"');
  res.status(401).json({ status: "error", error: "Invalid Authorization" });
}

const validate = (authorization) => {
  if (!authorization?.startsWith("Basic ")) return false;

  const base64 = authorization.split(" ")[1];
  const [name, pwd] = Buffer.from(base64, "base64").toString().split(":");
  return name === S_NAME && pwd === S_PWD;
};
const sendNotify = (notifyText) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.qq.com",
    port: 465,
    secure: true,
    auth: {
      user: U_EMAIL,
      pass: U_SMTP,
    },
  });

  const mailOptions = {
    from: U_EMAIL,
    to: U_EMAIL,
    subject: "Server Notify",
    text: notifyText,
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
    }
  });
};

async function sshConnect(res) {
  const conn = new ssh2.Client();
  return new Promise((resolve, reject) => {
    conn.connect({
      host: S_HOST,
      port: 22,
      username: S_NAME,
      password: S_PWD,
    });
    conn.on("ready", () => {
      sendNotify("SSH Connected");
      conn.end();
      res.status(200).json({ status: "success" });
      resolve(conn);
    });
    conn.on("error", (err) => {
      sendNotify("SSH Error: " + err);
      reject(err);
    });

    conn.on(
      "keyboard-interactive",
      (name, instructions, instructionsLang, prompts, finish) => {
        finish([S_PWD]);
      }
    );
    conn.on("change password", (message, language, done) => {
      done();
    });
  });
}
