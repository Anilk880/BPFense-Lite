# Demo

Run:

kubectl run test-pod --image=nginx

kubectl exec -it test-pod -- sh
cat /etc/passwd

Expected Output:

[AI] pod=test-pod score=0.2 severity=MEDIUM
[ACTION] ALERT
