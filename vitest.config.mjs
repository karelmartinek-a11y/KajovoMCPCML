export default {
  test: {
    fileParallelism: process.env.KCML_TEST_DATABASE === "1" ? false : true
  }
};
