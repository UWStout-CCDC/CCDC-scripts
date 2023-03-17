# E-comm server protection

## Prestashop

- [ ] Remove cronjobs module
- [ ] Compare install (/var/www/html/prestashop) to clean (zip file in /root)
- [ ] Break passwords in SQL (ps_customers & ps_employees)

## Rm

- [ ] Rename /bin/rm & /bin/unlink to make them inaccessible
  - [ ] Replace with a command to log any attempts to call rm/unlink
