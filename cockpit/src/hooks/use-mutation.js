import {useCallback, useState} from "react";
import {message} from "../lib/format.js";

export function useMutation(refresh) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const mutate = useCallback(
    async (operation, {successNotice = "Operation completed."} = {}) => {
      setBusy(true);
      setError("");
      setNotice("");
      try {
        const result = await operation();
        if (successNotice) setNotice(successNotice);
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
