const getSecretFromDB = async () => {
  
  try {
    // Simulate DB delay (120ms)
    await new Promise((resolve) => setTimeout(resolve, 120));

    const secret = process.env.APPLICATION_SECRET;

    if (!secret) {
      throw new Error(
        "APPLICATION_SECRET is not defined in environment variables."
      );
    }

    return secret;

  } catch (error) {
    console.error("Error fetching secret from DB:", error.message);
    throw error; // Re-throw so caller can handle it
  }
};

module.exports = { getSecretFromDB };
