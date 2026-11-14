
const express = require("express");
const crypto = require("crypto");
const admin = require("firebase-admin");

const app = express();
const PORT = process.env.PORT || 3000;

const SECRET = process.env.OFFERWALL_SECRET;
const PUBLIC_KEY = process.env.OFFERWALL_PUBLIC_KEY;
const SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!SECRET || !PUBLIC_KEY || !SERVICE_ACCOUNT_JSON) {
  throw new Error("Missing required environment variables");
}

const serviceAccount = JSON.parse(SERVICE_ACCOUNT_JSON);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

const wallets = db.collection("offerwall_gg_wallets");
const transactions = db.collection("offerwall_gg_transactions");

app.get("/", (req, res) => {
  res.status(200).send("MyContest Offerwall.GG Backend Running");
});

// Generate signed wall URL for authenticated Firebase user
app.get("/signed-wall", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const idToken = authHeader.substring(7);
    const decoded = await admin.auth().verifyIdToken(idToken);
    const userId = decoded.uid;

    const params = {
      appId: PUBLIC_KEY,
      userId: userId,
    };

    const canonical = Object.keys(params)
      .sort()
      .map((key) => `${key}=${params[key]}`)
      .join("&");

    const signature = crypto
      .createHmac("sha256", SECRET)
      .update(canonical)
      .digest("hex");

    const wallUrl =
      `https://offerwall.gg/wall/${PUBLIC_KEY}` +
      `?userId=${encodeURIComponent(userId)}` +
      `&signature=${signature}`;

    return res.status(200).json({
      success: true,
      wallUrl: wallUrl,
    });
  } catch (error) {
    console.error("Signed wall error:", error);
    return res.status(401).json({ error: "Unauthorized" });
  }
});

// Offerwall.GG Postback
app.get("/offerwall", async (req, res) => {
  try {
    const {
      user,
      tx,
      amount,
      status,
      test = "0",
      sig,
      currencyName,
      offerId,
      offerName,
      goalId,
      payoutUsd,
    } = req.query;

    if (
      typeof user !== "string" ||
      typeof tx !== "string" ||
      typeof amount !== "string" ||
      typeof status !== "string" ||
      typeof sig !== "string"
    ) {
      return res.status(400).send("Missing parameters");
    }

    if (!["credited", "reversed"].includes(status)) {
      return res.status(400).send("Invalid status");
    }

    const signatureData = `${user}:${tx}:${amount}`;

    const expected = crypto
      .createHmac("sha256", SECRET)
      .update(signatureData)
      .digest("hex");

    if (!/^[a-fA-F0-9]{64}$/.test(sig)) {
      return res.status(403).send("Invalid signature");
    }

    const receivedBuffer = Buffer.from(sig, "hex");
    const expectedBuffer = Buffer.from(expected, "hex");

    if (!crypto.timingSafeEqual(receivedBuffer, expectedBuffer)) {
      return res.status(403).send("Invalid signature");
    }

    // Never credit test postbacks
    if (test === "1") {
      return res.status(200).send("ok");
    }

    if (test !== "0") {
      return res.status(400).send("Invalid test value");
    }

    const points = Number(amount);

    if (!Number.isFinite(points) || points === 0) {
      return res.status(400).send("Invalid amount");
    }

    if (
      (status === "credited" && points <= 0) ||
      (status === "reversed" && points >= 0)
    ) {
      return res.status(400).send("Invalid amount for status");
    }

    if (!/^[a-zA-Z0-9_-]{1,128}$/.test(user)) {
      return res.status(400).send("Invalid user ID");
    }

    if (tx.length > 200) {
      return res.status(400).send("Invalid transaction ID");
    }

    const walletRef = wallets.doc(user);

    const transactionDocId = crypto
      .createHash("sha256")
      .update(tx)
      .digest("hex");

    const transactionRef = transactions.doc(transactionDocId);

    await db.runTransaction(async (t) => {
      const transactionSnap = await t.get(transactionRef);
      const walletSnap = await t.get(walletRef);

      const oldTransaction = transactionSnap.exists
        ? transactionSnap.data()
        : null;

      if (oldTransaction && oldTransaction.userId !== user) {
        throw new Error("Transaction user mismatch");
      }

      const currentBalance = walletSnap.exists
        ? Number(walletSnap.data().points || 0)
        : 0;

      if (!Number.isFinite(currentBalance) || currentBalance < 0) {
        throw new Error("Invalid wallet balance");
      }

      if (status === "credited") {
        // Prevent duplicate credits
        if (oldTransaction) {
          return;
        }

        t.set(walletRef, {
          userId: user,
          points: currentBalance + points,
          currencyName: currencyName || "Point",
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        t.set(transactionRef, {
          userId: user,
          transactionId: tx,
          points: points,
          status: "credited",
          currencyName: currencyName || "Point",
          offerId: offerId || "",
          offerName: offerName || "",
          goalId: goalId || "",
          payoutUsd: payoutUsd || "",
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

      } else {
        // Reverse only an existing credited transaction
        if (!oldTransaction || oldTransaction.status !== "credited") {
          return;
        }

        const reversalPoints = Number(oldTransaction.points);

        if (!Number.isFinite(reversalPoints) || reversalPoints <= 0) {
          throw new Error("Invalid original points");
        }

        if (currentBalance < reversalPoints) {
          throw new Error("Insufficient wallet balance");
        }

        t.set(walletRef, {
          userId: user,
          points: currentBalance - reversalPoints,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        t.update(transactionRef, {
          status: "reversed",
          reversedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }
    });

    return res.status(200).send("ok");

  } catch (error) {
    console.error("Offerwall postback error:", error);
    return res.status(500).send("Server error");
  }
});

app.listen(PORT, () => {
  console.log(`Offerwall.GG backend running on port ${PORT}`);
});
