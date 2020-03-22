from django.db import models
from django.contrib.auth.models import User

class Expense(models.Model):
    text = models.CharField(max_length = 255)
    date = models.DateTimeField()
    amount = models.BigIntegerField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name = 'expense')

    def __str__(self):
        return '{}-{}'.format(self.date, self.amount)


class Income(models.Model):
    text = models.CharField(max_length = 255)
    date = models.DateTimeField()
    amount = models.BigIntegerField()
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name = 'income')

    def __str__(self):
        return '{}-{}'.format(self.date, self.amount)
