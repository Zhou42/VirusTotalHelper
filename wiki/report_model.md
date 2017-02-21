# Data Model for Reports

`hash_value`, `Fortinet_detection`, `detected_number`, `scan_date` are the required fields for the output.
`user_email` is the email of the user that uploads the file. `filename` is the filename of the file that hash belongs to. `scanned` represents whether hash is valid and corresponds to a scanned file. 

| Parameters              | Type                                                                      |
|-------------------|----------------------------------------------------------------------------|
| `hash_value`              | String                                         |
| `Fortinet_detection`              | String                                         |
| `detected_number`              | Integer                                         |
| `scan_date`            | DateTime                                         |
| `user_email`            | String                                         |
| `filename`            | String                                         |
| `scanned`            | Boolean                                         |