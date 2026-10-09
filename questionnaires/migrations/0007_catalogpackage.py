from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('questionnaires', '0006_exchangepackage_workflow_status'),
    ]

    operations = [
        migrations.CreateModel(
            name='CatalogPackage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kind', models.CharField(max_length=10)),
                ('from_version', models.BigIntegerField(default=0)),
                ('to_version', models.BigIntegerField(db_index=True)),
                ('data', models.BinaryField()),
                ('size', models.BigIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AddConstraint(
            model_name='catalogpackage',
            constraint=models.UniqueConstraint(fields=('kind', 'from_version', 'to_version'), name='unique_catalog_package'),
        ),
    ]
