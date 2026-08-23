import {useCallback, useState} from "react";
import {message} from "../lib/format.js";

export function useMutation(refresh) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const mutate = useCallback(
    async (operation) => {
      setBusy(true);
      setError("");
      setNotice("");
      try {
        const result = await operation();
        setNotice("Operation completed.");
        await refresh();
        return result;
      } catch (reason) {
        setError(message(reason));
        throw reason;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  return {busy, error, notice, setError, setNotice, mutate};
}
