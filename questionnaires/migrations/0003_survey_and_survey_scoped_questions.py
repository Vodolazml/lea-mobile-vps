import django.db.models.deletion
from django.db import migrations, models


def clear_unscoped_questions(apps, schema_editor):
    """SurveyQuestion here is a pure read-through cache (local_survey_schema_sync fully
    replaces it every sync run) — nothing worth preserving across this shape change, and it
    refreshes itself on the very next sync."""
    SurveyQuestionOption = apps.get_model("questionnaires", "SurveyQuestionOption")
    SurveyQuestion = apps.get_model("questionnaires", "SurveyQuestion")
    SurveyQuestionOption.objects.all().delete()
    SurveyQuestion.objects.all().delete()


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('questionnaires', '0002_surveyquestion_surveyquestionoption'),
    ]

    operations = [
        migrations.CreateModel(
            name='Survey',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('key', models.CharField(max_length=40, unique=True)),
                ('name', models.CharField(max_length=200)),
                ('description', models.CharField(blank=True, max_length=500)),
                ('sort', models.PositiveIntegerField(default=100)),
            ],
            options={
                'ordering': ['sort', 'id'],
            },
        ),
        migrations.RunPython(clear_unscoped_questions, noop),
        migrations.AddField(
            model_name='surveyquestion',
            name='survey',
            field=models.ForeignKey(default=None, on_delete=django.db.models.deletion.CASCADE, related_name='questions', to='questionnaires.survey'),
            preserve_default=False,
        ),
    ]
