using DeleteGuard.Core.Services;
using DeleteGuard.EventRelay;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "DeleteGuard Event Relay";
});
builder.Services.AddSingleton<DeniedDeleteEventStore>();
builder.Services.AddHostedService<RelayWorker>();

await builder.Build().RunAsync();
