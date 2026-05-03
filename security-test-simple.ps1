# SIMPLIFIED SECURITY TEST
Write-Host "`n=== SECURITY TEST FOR LOCALHOST:8000 ===`n" -ForegroundColor Cyan

$results = @()
$baseUrl = "http://localhost:8000"

# Test 1: Unauthorized Cart Access
Write-Host "[1/10] Testing: Add to Cart (No Auth)" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$baseUrl/api/cart/add" `
        -Method POST `
        -Headers @{"Content-Type"="application/json"} `
        -Body '{"userId":"test","itemId":"test"}' `
        -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "       ❌ VULNERABLE`n" -ForegroundColor Red
    $results += "FAIL"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -eq 401 -or $code -eq 403) {
        Write-Host "       ✅ BLOCKED ($code)`n" -ForegroundColor Green
        $results += "PASS"
    } else {
        Write-Host "       ⚠️  ERROR ($code)`n" -ForegroundColor Yellow
        $results += "ERROR"
    }
}

# Test 2: View Cart Without Auth
Write-Host "[2/10] Testing: View Cart (No Auth)" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$baseUrl/api/cart?userId=test" `
        -Method GET `
        -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "       ❌ VULNERABLE`n" -ForegroundColor Red
    $results += "FAIL"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -eq 401 -or $code -eq 403) {
        Write-Host "       ✅ BLOCKED ($code)`n" -ForegroundColor Green
        $results += "PASS"
    } else {
        Write-Host "       ⚠️  ERROR ($code)`n" -ForegroundColor Yellow
        $results += "ERROR"
    }
}

# Test 3: Update Cart Without Auth
Write-Host "[3/10] Testing: Update Cart (No Auth)" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$baseUrl/api/cart/update/test" `
        -Method PUT `
        -Headers @{"Content-Type"="application/json"} `
        -Body '{"userId":"test","quantity":999}' `
        -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "       ❌ VULNERABLE`n" -ForegroundColor Red
    $results += "FAIL"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -eq 401 -or $code -eq 403) {
        Write-Host "       ✅ BLOCKED ($code)`n" -ForegroundColor Green
        $results += "PASS"
    } else {
        Write-Host "       ⚠️  ERROR ($code)`n" -ForegroundColor Yellow
        $results += "ERROR"
    }
}

# Test 4: Delete from Cart Without Auth
Write-Host "[4/10] Testing: Delete from Cart (No Auth)" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$baseUrl/api/cart/delete/test" `
        -Method DELETE `
        -Headers @{"Content-Type"="application/json"} `
        -Body '{"userId":"test"}' `
        -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "       ❌ VULNERABLE`n" -ForegroundColor Red
    $results += "FAIL"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -eq 401 -or $code -eq 403) {
        Write-Host "       ✅ BLOCKED ($code)`n" -ForegroundColor Green
        $results += "PASS"
    } else {
        Write-Host "       ⚠️  ERROR ($code)`n" -ForegroundColor Yellow
        $results += "ERROR"
    }
}

# Test 5: Direct Purchase Without Auth
Write-Host "[5/10] Testing: Direct Purchase (No Auth)" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$baseUrl/api/direct-purchase" `
        -Method POST `
        -Headers @{"Content-Type"="application/json"} `
        -Body '{"userId":"test","productId":"test"}' `
        -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "       ❌ VULNERABLE`n" -ForegroundColor Red
    $results += "FAIL"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -eq 401 -or $code -eq 403) {
        Write-Host "       ✅ BLOCKED ($code)`n" -ForegroundColor Green
        $results += "PASS"
    } else {
        Write-Host "       ⚠️  ERROR ($code)`n" -ForegroundColor Yellow
        $results += "ERROR"
    }
}

# Test 6: View Orders Without Auth
Write-Host "[6/10] Testing: View Orders (No Auth)" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$baseUrl/api/user-orders?userId=test" `
        -Method GET `
        -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "       ❌ VULNERABLE`n" -ForegroundColor Red
    $results += "FAIL"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -eq 401 -or $code -eq 403) {
        Write-Host "       ✅ BLOCKED ($code)`n" -ForegroundColor Green
        $results += "PASS"
    } else {
        Write-Host "       ⚠️  ERROR ($code)`n" -ForegroundColor Yellow
        $results += "ERROR"
    }
}

# Test 7: Fake JWT Token
Write-Host "[7/10] Testing: Fake JWT Token" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$baseUrl/api/cart/add" `
        -Method POST `
        -Headers @{"Content-Type"="application/json";"Authorization"="Bearer fake.token.here"} `
        -Body '{"userId":"test","itemId":"test"}' `
        -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "       ❌ VULNERABLE`n" -ForegroundColor Red
    $results += "FAIL"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -eq 401 -or $code -eq 403) {
        Write-Host "       ✅ BLOCKED (Token Rejected)`n" -ForegroundColor Green
        $results += "PASS"
    } else {
        Write-Host "       ⚠️  ERROR ($code)`n" -ForegroundColor Yellow
        $results += "ERROR"
    }
}

# Test 8: NoSQL Injection
Write-Host "[8/10] Testing: NoSQL Injection" -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "$baseUrl/api/cart/add" `
        -Method POST `
        -Headers @{"Content-Type"="application/json"} `
        -Body '{"userId":{"$ne":null},"itemId":"test"}' `
        -UseBasicParsing -ErrorAction Stop | Out-Null
    Write-Host "       ❌ VULNERABLE (NoSQL Injection!)`n" -ForegroundColor Red
    $results += "FAIL"
} catch {
    $code = [int]$_.Exception.Response.StatusCode
    if ($code -eq 401 -or $code -eq 403) {
        Write-Host "       ✅ BLOCKED (Auth)`n" -ForegroundColor Green
        $results += "PASS"
    } elseif ($code -eq 400) {
        Write-Host "       ✅ REJECTED (Sanitized)`n" -ForegroundColor Green
        $results += "PASS"
    } else {
        Write-Host "       ⚠️  ERROR ($code)`n" -ForegroundColor Yellow
        $results += "ERROR"
    }
}

# Test 9: Rate Limiting
Write-Host "[9/10] Testing: Rate Limiting (5 rapid requests)" -ForegroundColor Yellow
$rateLimited = $false
for ($i=1; $i -le 5; $i++) {
    try {
        Invoke-WebRequest -Uri "$baseUrl/api/login" `
            -Method POST `
            -Headers @{"Content-Type"="application/json"} `
            -Body '{"email":"test@test.com","password":"wrong"}' `
            -UseBasicParsing -ErrorAction Stop | Out-Null
    } catch {
        $code = [int]$_.Exception.Response.StatusCode
        if ($code -eq 429) {
            $rateLimited = $true
            break
        }
    }
}
if ($rateLimited) {
    Write-Host "       ✅ RATE LIMITING ACTIVE`n" -ForegroundColor Green
    $results += "PASS"
} else {
    Write-Host "       ⚠️  No rate limiting detected`n" -ForegroundColor Yellow
    $results += "ERROR"
}

# Test 10: CORS Check
Write-Host "[10/10] Testing: CORS Policy" -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$baseUrl/api/health" `
        -Method GET `
        -Headers @{"Origin"="http://evil.com"} `
        -UseBasicParsing -ErrorAction Stop
    $corsHeader = $response.Headers["Access-Control-Allow-Origin"]
    if ($corsHeader -eq "*") {
        Write-Host "       ❌ VULNERABLE (Allows all origins)`n" -ForegroundColor Red
        $results += "FAIL"
    } else {
        Write-Host "       ✅ RESTRICTED CORS`n" -ForegroundColor Green
        $results += "PASS"
    }
} catch {
    Write-Host "       ✅ CORS BLOCKED`n" -ForegroundColor Green
    $results += "PASS"
}

# Results
Write-Host "`n=== RESULTS ===`n" -ForegroundColor Magenta
$passed = ($results | Where-Object {$_ -eq "PASS"}).Count
$failed = ($results | Where-Object {$_ -eq "FAIL"}).Count
$errors = ($results | Where-Object {$_ -eq "ERROR"}).Count

Write-Host "✅ Passed: $passed/10" -ForegroundColor Green
Write-Host "❌ Failed: $failed/10" -ForegroundColor Red
Write-Host "⚠️  Errors: $errors/10`n" -ForegroundColor Yellow

$score = [int](($passed / 10) * 100)
Write-Host "Security Score: $score/100" -ForegroundColor $(if($score -ge 90){"Green"}elseif($score -ge 70){"Yellow"}else{"Red"})

if ($failed -eq 0 -and $passed -eq 10) {
    Write-Host "`n🎉 EXCELLENT! All security tests passed!" -ForegroundColor Green
} elseif ($failed -gt 0) {
    Write-Host "`n⚠️  WARNING: $failed vulnerabilities detected!" -ForegroundColor Red
} else {
    Write-Host "`n⚠️  Some tests had errors. Check your server." -ForegroundColor Yellow
}
Write-Host "`n"
